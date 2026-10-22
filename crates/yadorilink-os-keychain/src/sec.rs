//! The system backend: [`Attr`] lists as CFDictionaries for `SecItem*`.
//! Nothing here is exercised by the unit tests (no keychain off-device); the
//! attribute sets that reach it are.

use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::item::{
    kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
    kSecClassGenericPassword, kSecMatchLimit, kSecReturnData, kSecUseDataProtectionKeychain,
    kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};

use crate::{Attr, Backend, Status};

// Two Security.framework constants the sys crate does not declare.
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecAttrAccessible: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
}

/// `SecItemAdd` / `SecItemUpdate` / `SecItemCopyMatching` / `SecItemDelete`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecItems;

fn constant(s: CFStringRef) -> CFType {
    // SAFETY: `s` is one of Security.framework's constant CFStrings, which live
    // for the whole process; the get rule retains it for the wrapper.
    unsafe { CFString::wrap_under_get_rule(s) }.as_CFType()
}

fn string(s: &str) -> CFType {
    CFString::new(s).as_CFType()
}

fn pair(attr: &Attr) -> (CFType, CFType) {
    // SAFETY: reading Security.framework's extern constant statics.
    unsafe {
        match attr {
            Attr::ClassGenericPassword => (constant(kSecClass), constant(kSecClassGenericPassword)),
            Attr::Service(v) => (constant(kSecAttrService), string(v)),
            Attr::Account(v) => (constant(kSecAttrAccount), string(v)),
            Attr::AccessGroup(v) => (constant(kSecAttrAccessGroup), string(v)),
            Attr::UseDataProtectionKeychain(v) => {
                (constant(kSecUseDataProtectionKeychain), CFBoolean::from(*v).as_CFType())
            }
            Attr::Synchronizable(v) => {
                (constant(kSecAttrSynchronizable), CFBoolean::from(*v).as_CFType())
            }
            Attr::AccessibleAfterFirstUnlockThisDeviceOnly => (
                constant(kSecAttrAccessible),
                constant(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            ),
            Attr::ValueData(v) => (constant(kSecValueData), CFData::from_buffer(v).as_CFType()),
            Attr::ReturnData(v) => (constant(kSecReturnData), CFBoolean::from(*v).as_CFType()),
            Attr::MatchLimitOne => (constant(kSecMatchLimit), constant(kSecMatchLimitOne)),
        }
    }
}

fn dictionary(attrs: &[Attr]) -> CFDictionary<CFType, CFType> {
    let pairs: Vec<(CFType, CFType)> = attrs.iter().map(pair).collect();
    CFDictionary::from_CFType_pairs(&pairs)
}

fn check(code: i32) -> Result<(), Status> {
    if code == errSecSuccess {
        Ok(())
    } else {
        Err(Status::from_os_status(code))
    }
}

impl Backend for SecItems {
    fn add(&self, attributes: &[Attr]) -> Result<(), Status> {
        let dict = dictionary(attributes);
        // SAFETY: `dict` is a valid CFDictionary; no result is requested.
        check(unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) })
    }

    fn update(&self, query: &[Attr], changes: &[Attr]) -> Result<(), Status> {
        let (query, changes) = (dictionary(query), dictionary(changes));
        // SAFETY: both are valid CFDictionaries that outlive the call.
        check(unsafe { SecItemUpdate(query.as_concrete_TypeRef(), changes.as_concrete_TypeRef()) })
    }

    fn copy_data(&self, query: &[Attr]) -> Result<Vec<u8>, Status> {
        let dict = dictionary(query);
        let mut result: CFTypeRef = std::ptr::null();
        // SAFETY: `dict` is valid; on success `result` is a +1 reference we own.
        check(unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) })?;
        if result.is_null() {
            return Err(Status::NotFound);
        }
        // SAFETY: SecItemCopyMatching returned an owned (create-rule) object.
        let value = unsafe { CFType::wrap_under_create_rule(result) };
        value.downcast_into::<CFData>().map(|data| data.bytes().to_vec()).ok_or(Status::Other(-1))
    }

    fn delete(&self, query: &[Attr]) -> Result<(), Status> {
        let dict = dictionary(query);
        // SAFETY: `dict` is a valid CFDictionary that outlives the call.
        check(unsafe { SecItemDelete(dict.as_concrete_TypeRef()) })
    }
}
