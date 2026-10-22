//! Verifying who serves a local named pipe.
//!
//! A Windows named-pipe name is global to the machine and the first process
//! to create it wins, so a client that merely connects to
//! `\\.\pipe\yadorilink-ctl-<user>` cannot tell the daemon from another local
//! user's process that created the pipe first. Clients therefore compare the
//! account that owns the pipe server's process with their own before sending
//! anything over it.

/// Whether two binary SIDs name the same account.
///
/// Both must be well-formed (`SID`: revision 1, at most 15 sub-authorities,
/// exactly `8 + 4 * count` bytes); anything else never matches, so a
/// truncated or garbage buffer cannot be mistaken for the current user.
pub fn sids_match(a: &[u8], b: &[u8]) -> bool {
    well_formed_sid(a) && well_formed_sid(b) && a == b
}

fn well_formed_sid(sid: &[u8]) -> bool {
    const REVISION: u8 = 1;
    const MAX_SUB_AUTHORITIES: usize = 15;
    if sid.len() < 8 || sid[0] != REVISION {
        return false;
    }
    let sub_authorities = usize::from(sid[1]);
    sub_authorities <= MAX_SUB_AUTHORITIES && sid.len() == 8 + 4 * sub_authorities
}

/// Fails with `PermissionDenied` unless the process serving `pipe` runs as the
/// same user as this process.
#[cfg(windows)]
pub fn verify_pipe_server_is_current_user(
    pipe: &impl std::os::windows::io::AsRawHandle,
) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// The user SID of the token of `process_id`, as bytes.
    fn user_sid_of_process(process_id: u32) -> std::io::Result<Vec<u8>> {
        // SAFETY: plain Win32 calls; every handle opened here is closed on
        // every path before returning, and the SID is copied out of the
        // token-information buffer before that buffer is dropped.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id);
            if process.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let mut token: HANDLE = std::ptr::null_mut();
            let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token);
            let open_error = std::io::Error::last_os_error();
            CloseHandle(process);
            if opened == 0 {
                return Err(open_error);
            }

            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            let mut buffer = vec![0u8; len as usize];
            let read =
                GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len);
            let read_error = std::io::Error::last_os_error();
            CloseHandle(token);
            if read == 0 {
                return Err(read_error);
            }

            let token_user = buffer.as_ptr().cast::<TOKEN_USER>().read_unaligned();
            let sid = token_user.User.Sid;
            let sid_len = GetLengthSid(sid) as usize;
            Ok(std::slice::from_raw_parts(sid.cast::<u8>(), sid_len).to_vec())
        }
    }

    let mut server_pid = 0u32;
    // SAFETY: `pipe` is a live pipe handle for the duration of the call.
    let ok = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server_pid) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let server = user_sid_of_process(server_pid)?;
    let current = user_sid_of_process(std::process::id())?;
    if sids_match(&server, &current) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the named pipe is served by a process running as a different user",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::sids_match;

    /// `S-1-5-21-1-2-3-1001`: revision 1, 5 sub-authorities.
    fn sid(rid: u32) -> Vec<u8> {
        let mut sid = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3, rid] {
            sid.extend_from_slice(&sub.to_le_bytes());
        }
        sid
    }

    #[test]
    fn the_same_account_matches() {
        assert!(sids_match(&sid(1001), &sid(1001)));
    }

    #[test]
    fn a_different_account_does_not_match() {
        assert!(!sids_match(&sid(1001), &sid(1002)));
    }

    #[test]
    fn malformed_sids_never_match_even_when_identical() {
        let truncated = sid(1001)[..10].to_vec();
        assert!(!sids_match(&truncated, &truncated));
        assert!(!sids_match(&[], &[]));
        let mut wrong_revision = sid(1001);
        wrong_revision[0] = 2;
        assert!(!sids_match(&wrong_revision, &wrong_revision));
        let mut wrong_count = sid(1001);
        wrong_count[1] = 4;
        assert!(!sids_match(&wrong_count, &wrong_count));
    }
}
