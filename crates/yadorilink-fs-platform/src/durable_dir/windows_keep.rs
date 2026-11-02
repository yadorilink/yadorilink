//! What a replacing move keeps of the file it replaces, on Windows.
//!
//! `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` is the one write-through primitive the namespace is built on
//! (see `super::raw`), and it makes the target the staged file as it is: the staged file's inherited ACL, its
//! default attributes. Two things followed that a person notices. A target the person marked read-only is
//! refused with "access denied" for ever, so a synchronised update never lands on it; and an update that does
//! land drops the explicit access control entries the person put on the file and its hidden/system
//! attributes.
//!
//! [`Kept::prepare`] runs just before the move: it copies the target's hidden/system/read-only attributes and
//! its DACL to the staged file (the DACL only when it carries something the staged file would not inherit
//! anyway: a protected DACL or an explicit entry), and clears the target's read-only attribute so the move can
//! replace it. The read-only mark then travels with the staged file. If the move fails, [`Kept::undo`] puts
//! the target's attributes back and removes the read-only mark from the staged file (a read-only stage could
//! not be cleaned up).
//!
//! Not kept, on purpose: alternate data streams (the replaced bytes' origin marks do not describe new bytes),
//! owner and group (the new file belongs to the writer), a reparse point (a Cloud Files placeholder is the
//! platform's to manage; it is moved as before).

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM,
    INVALID_FILE_ATTRIBUTES,
};

/// SE_DACL_PROTECTED of a security descriptor's control word.
const SE_DACL_PROTECTED: u16 = 0x1000;
const KEPT_ATTRIBUTES: u32 =
    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY;

pub(super) struct Kept {
    stage: Vec<u16>,
    target: Vec<u16>,
    stage_attributes: u32,
    target_attributes: u32,
    /// The staged file's own DACL before the target's was copied onto it, put back if the move fails.
    stage_dacl: Option<SavedDacl>,
}

fn attributes(path: &[u16]) -> Option<u32> {
    // SAFETY: `path` is NUL-terminated and outlives the call.
    let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
    (attributes != INVALID_FILE_ATTRIBUTES).then_some(attributes)
}

impl Kept {
    /// `Ok(None)` when there is nothing to keep: the target is absent, a directory or a reparse point.
    /// An `Err` stops the publish before anything was moved: the staged file could not be given what the
    /// replaced file's owner set on it (the staged file is left as it was).
    pub(super) fn prepare(stage: &[u16], target: &[u16]) -> std::io::Result<Option<Kept>> {
        let Some(target_attributes) = attributes(target) else { return Ok(None) };
        if target_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Ok(None);
        }
        let Some(stage_attributes) = attributes(stage) else { return Ok(None) };
        let mut kept = Kept {
            stage: stage.to_vec(),
            target: target.to_vec(),
            stage_attributes,
            target_attributes,
            stage_dacl: None,
        };
        // Attributes first, while the staged file is still ours alone: copying a DACL that denies this
        // process the right to write attributes would otherwise make this step fail afterwards.
        let wanted = (stage_attributes & !KEPT_ATTRIBUTES) | (target_attributes & KEPT_ATTRIBUTES);
        if wanted != stage_attributes {
            // SAFETY: NUL-terminated and outlives the call.
            if unsafe { SetFileAttributesW(stage.as_ptr(), wanted) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        // The DACL last: it is the step that can open the staged file to others, so it comes immediately
        // before the move and is taken back if the move does not happen.
        match copy_dacl_if_explicit(target, stage) {
            Ok(saved) => kept.stage_dacl = saved,
            Err(error) => {
                kept.undo();
                return Err(error);
            }
        }
        if target_attributes & FILE_ATTRIBUTE_READONLY != 0 {
            // The replace is refused while the mark stands.
            // SAFETY: NUL-terminated and outlives the call.
            if unsafe {
                SetFileAttributesW(target.as_ptr(), target_attributes & !FILE_ATTRIBUTE_READONLY)
            } == 0
            {
                let error = std::io::Error::last_os_error();
                kept.undo();
                return Err(error);
            }
        }
        Ok(Some(kept))
    }

    /// After a move that did not happen: the staged file is as it was (attributes and DACL) and the
    /// target keeps its read-only mark, unless the name now holds a different object (renamed away and
    /// replaced meanwhile), which is left alone.
    pub(super) fn undo(&self) {
        // SAFETY: NUL-terminated and outlive the calls.
        unsafe {
            if self.target_attributes & FILE_ATTRIBUTE_READONLY != 0 {
                if let Some(now) = attributes(&self.target) {
                    // Only the object prepare cleared: a regular file whose attributes are exactly the
                    // cleared ones.
                    let cleared = self.target_attributes & !FILE_ATTRIBUTE_READONLY;
                    if now == cleared {
                        SetFileAttributesW(self.target.as_ptr(), self.target_attributes);
                    }
                }
            }
            if let Some(saved) = &self.stage_dacl {
                saved.put_back(&self.stage);
            }
            if attributes(&self.stage).is_some() {
                SetFileAttributesW(self.stage.as_ptr(), self.stage_attributes);
            }
        }
    }
}

/// A security descriptor returned by `GetNamedSecurityInfoW`, freed when dropped.
struct SavedDacl {
    descriptor: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
    protected: bool,
}

impl SavedDacl {
    fn read(path: &[u16]) -> std::io::Result<SavedDacl> {
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: out pointers are valid; `path` is NUL-terminated.
        let status = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 || descriptor.is_null() {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        // A NULL DACL is a descriptor to free like any other.
        Ok(SavedDacl { descriptor, dacl, protected: descriptor_is_protected(descriptor) })
    }

    fn explicit(&self) -> bool {
        !self.dacl.is_null() && (self.protected || acl_holds_an_explicit_entry(self.dacl))
    }

    fn apply(&self, path: &[u16]) -> std::io::Result<()> {
        let flags = if self.protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        // SAFETY: `path` is NUL-terminated; `dacl` belongs to `descriptor`, alive until drop.
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr().cast_mut(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | flags,
                null_mut(),
                null_mut(),
                self.dacl,
                null(),
            )
        };
        // The call returns its error code; it does not set the thread's last error.
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(status as i32))
        }
    }

    fn put_back(&self, path: &[u16]) {
        let _ = self.apply(path);
    }
}

impl Drop for SavedDacl {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by `GetNamedSecurityInfoW`.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// Copies the DACL of `from` to `to` when it holds an entry that is not inherited or is protected from
/// inheritance: the cases where the staged file would otherwise end up with different access. Returns the
/// staged file's own previous DACL (to put back if the move fails), or `None` when nothing was copied.
fn copy_dacl_if_explicit(from: &[u16], to: &[u16]) -> std::io::Result<Option<SavedDacl>> {
    // A DACL that cannot be read is not silently dropped: the publish stops.
    let source = SavedDacl::read(from)?;
    if !source.explicit() {
        return Ok(None);
    }
    // The staged file's own DACL is needed to put back if the move does not happen.
    let own = SavedDacl::read(to)?;
    source.apply(to)?;
    Ok(Some(own))
}

fn acl_holds_an_explicit_entry(acl: *mut ACL) -> bool {
    let mut info = ACL_SIZE_INFORMATION { AceCount: 0, AclBytesInUse: 0, AclBytesFree: 0 };
    // SAFETY: `info` is the size the call expects.
    let ok = unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return false;
    }
    for index in 0..info.AceCount {
        let mut ace: *mut core::ffi::c_void = null_mut();
        // SAFETY: `index` is below the entry count.
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
            continue;
        }
        // ACE_HEADER: AceType u8, AceFlags u8, AceSize u16.
        // SAFETY: every ACE starts with its 4-byte header.
        let flags = unsafe { *(ace as *const u8).add(1) };
        if u32::from(flags) & INHERITED_ACE == 0 {
            return true;
        }
    }
    false
}

fn descriptor_is_protected(descriptor: PSECURITY_DESCRIPTOR) -> bool {
    use windows_sys::Win32::Security::GetSecurityDescriptorControl;
    let (mut control, mut revision) = (0u16, 0u32);
    // SAFETY: out pointers are valid.
    let ok = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
    ok != 0 && control & SE_DACL_PROTECTED != 0
}
