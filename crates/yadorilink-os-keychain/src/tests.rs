// apple-cfg-file: ios-explicit the iOS-simulator keychain test
//! Off-device tests: the attribute sets the crate builds, and its
//! update-or-add / absence / purge logic, over an in-memory backend. No
//! keychain is touched.

use std::cell::RefCell;
use std::collections::HashMap;

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Add(Vec<Attr>),
    Update(Vec<Attr>, Vec<Attr>),
    Copy(Vec<Attr>),
    Delete(Vec<Attr>),
}

/// Items keyed by account; every call is recorded verbatim.
#[derive(Default)]
struct Fake {
    items: RefCell<HashMap<String, Vec<u8>>>,
    calls: RefCell<Vec<Call>>,
    fail_with: RefCell<Option<Status>>,
    /// The first `add` finds the item already there (a concurrent writer).
    duplicate_once: RefCell<bool>,
}

fn account(attrs: &[Attr]) -> Option<String> {
    attrs.iter().find_map(|a| if let Attr::Account(v) = a { Some(v.clone()) } else { None })
}

fn value(attrs: &[Attr]) -> Option<Vec<u8>> {
    attrs.iter().find_map(|a| if let Attr::ValueData(v) = a { Some(v.clone()) } else { None })
}

impl Backend for &Fake {
    fn add(&self, attributes: &[Attr]) -> Result<(), Status> {
        self.calls.borrow_mut().push(Call::Add(attributes.to_vec()));
        if let Some(status) = *self.fail_with.borrow() {
            return Err(status);
        }
        let key = account(attributes).unwrap();
        if self.duplicate_once.replace(false) {
            self.items.borrow_mut().insert(key, b"raced".to_vec());
            return Err(Status::Duplicate);
        }
        if self.items.borrow().contains_key(&key) {
            return Err(Status::Duplicate);
        }
        self.items.borrow_mut().insert(key, value(attributes).unwrap());
        Ok(())
    }

    fn update(&self, query: &[Attr], changes: &[Attr]) -> Result<(), Status> {
        self.calls.borrow_mut().push(Call::Update(query.to_vec(), changes.to_vec()));
        if let Some(status) = *self.fail_with.borrow() {
            return Err(status);
        }
        match self.items.borrow_mut().get_mut(&account(query).unwrap()) {
            Some(slot) => {
                *slot = value(changes).unwrap();
                Ok(())
            }
            None => Err(Status::NotFound),
        }
    }

    fn copy_data(&self, query: &[Attr]) -> Result<Vec<u8>, Status> {
        self.calls.borrow_mut().push(Call::Copy(query.to_vec()));
        if let Some(status) = *self.fail_with.borrow() {
            return Err(status);
        }
        self.items.borrow().get(&account(query).unwrap()).cloned().ok_or(Status::NotFound)
    }

    fn delete(&self, query: &[Attr]) -> Result<(), Status> {
        self.calls.borrow_mut().push(Call::Delete(query.to_vec()));
        if let Some(status) = *self.fail_with.borrow() {
            return Err(status);
        }
        let mut items = self.items.borrow_mut();
        let before = items.len();
        match account(query) {
            Some(a) => {
                items.remove(&a);
            }
            None => items.clear(),
        }
        if before == 0 {
            Err(Status::NotFound)
        } else {
            Ok(())
        }
    }
}

fn identity_attrs() -> Vec<Attr> {
    vec![
        Attr::ClassGenericPassword,
        Attr::Service("yadorilink".into()),
        Attr::AccessGroup(ACCESS_GROUP.into()),
        Attr::UseDataProtectionKeychain(true),
        Attr::Synchronizable(false),
    ]
}

fn assert_identity(attrs: &[Attr], expect_account: Option<&str>) {
    for want in identity_attrs() {
        assert!(attrs.contains(&want), "missing {want:?} in {attrs:?}");
    }
    assert_eq!(account(attrs).as_deref(), expect_account, "{attrs:?}");
}

#[test]
fn the_group_and_service_are_the_ones_the_entitlements_name() {
    assert_eq!(MACOS_ACCESS_GROUP, "594UQF7QX3.com.juntaki.yadorilink.credentials");
    assert_eq!(IOS_ACCESS_GROUP, "594UQF7QX3.com.juntaki.yadorilink.ios.shared");
    assert_ne!(MACOS_ACCESS_GROUP, IOS_ACCESS_GROUP);
    let expected = if cfg!(target_os = "ios") { IOS_ACCESS_GROUP } else { MACOS_ACCESS_GROUP };
    assert_eq!(ACCESS_GROUP, expected);
    assert_eq!(SERVICE, "yadorilink");
}

#[test]
fn a_first_write_updates_then_adds_with_every_identity_attribute_and_the_accessibility() {
    let fake = Fake::default();
    Keychain::new(&fake).write("credentials", b"doc").unwrap();
    let calls = fake.calls.borrow();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let Call::Update(query, changes) = &calls[0] else { panic!("{calls:?}") };
    assert_identity(query, Some("credentials"));
    assert!(!query.iter().any(|a| matches!(a, Attr::ValueData(_))));
    assert_eq!(
        changes,
        &[Attr::ValueData(b"doc".to_vec()), Attr::AccessibleAfterFirstUnlockThisDeviceOnly]
    );
    let Call::Add(item) = &calls[1] else { panic!("{calls:?}") };
    assert_identity(item, Some("credentials"));
    assert!(item.contains(&Attr::ValueData(b"doc".to_vec())));
    assert!(item.contains(&Attr::AccessibleAfterFirstUnlockThisDeviceOnly));
    assert_eq!(fake.items.borrow().get("credentials").unwrap(), b"doc");
}

#[test]
fn an_existing_item_is_replaced_by_update_alone() {
    let fake = Fake::default();
    let kc = Keychain::new(&fake);
    kc.write("credentials", b"one").unwrap();
    fake.calls.borrow_mut().clear();
    kc.write("credentials", b"two").unwrap();
    assert!(matches!(fake.calls.borrow().as_slice(), [Call::Update(..)]));
    assert_eq!(kc.read("credentials").unwrap().unwrap(), b"two");
}

#[test]
fn losing_the_add_race_replaces_what_the_other_writer_stored() {
    let fake = Fake::default();
    *fake.duplicate_once.borrow_mut() = true;
    Keychain::new(&fake).write("credentials", b"mine").unwrap();
    assert_eq!(fake.items.borrow().get("credentials").unwrap(), b"mine");
    assert_eq!(fake.calls.borrow().len(), 3);
}

#[test]
fn read_asks_for_data_of_exactly_one_item_with_the_full_identity() {
    let fake = Fake::default();
    assert_eq!(
        Keychain::new(&fake).read("credentials").unwrap(),
        None,
        "no item is absence, not an error"
    );
    let calls = fake.calls.borrow();
    let Call::Copy(query) = &calls[0] else { panic!() };
    assert_identity(query, Some("credentials"));
    assert!(query.contains(&Attr::ReturnData(true)));
    assert!(query.contains(&Attr::MatchLimitOne));
}

#[test]
fn delete_is_idempotent_and_keyed_by_account() {
    let fake = Fake::default();
    let kc = Keychain::new(&fake);
    kc.delete("credentials").unwrap();
    kc.write("credentials", b"x").unwrap();
    kc.delete("credentials").unwrap();
    assert_eq!(kc.read("credentials").unwrap(), None);
    let calls = fake.calls.borrow();
    let Call::Delete(query) = &calls[0] else { panic!() };
    assert_identity(query, Some("credentials"));
}

#[test]
fn delete_all_names_the_group_but_no_account_so_it_takes_the_device_key_mirrors_too() {
    let fake = Fake::default();
    let kc = Keychain::new(&fake);
    kc.write("credentials", b"x").unwrap();
    kc.write("device-key:/a", b"y").unwrap();
    kc.delete_all().unwrap();
    assert!(fake.items.borrow().is_empty());
    kc.delete_all().unwrap(); // nothing left is fine
    let calls = fake.calls.borrow();
    let Call::Delete(query) = calls.iter().find(|c| matches!(c, Call::Delete(_))).unwrap() else {
        panic!()
    };
    assert_identity(query, None);
}

#[test]
fn no_query_or_item_ever_asks_for_a_legacy_keychain_or_sync() {
    let fake = Fake::default();
    let kc = Keychain::new(&fake);
    kc.write("credentials", b"x").unwrap();
    let _ = kc.read("credentials");
    kc.delete("credentials").unwrap();
    kc.delete_all().unwrap();
    for call in fake.calls.borrow().iter() {
        let attrs: Vec<&Attr> = match call {
            Call::Add(a) | Call::Copy(a) | Call::Delete(a) | Call::Update(a, _) => {
                a.iter().collect()
            }
        };
        assert!(attrs.contains(&&Attr::UseDataProtectionKeychain(true)), "{call:?}");
        assert!(attrs.contains(&&Attr::Synchronizable(false)), "{call:?}");
        assert!(!attrs.contains(&&Attr::UseDataProtectionKeychain(false)), "{call:?}");
    }
}

#[test]
fn a_failure_is_an_error_and_a_missing_entitlement_names_the_file_store() {
    let fake = Fake::default();
    *fake.fail_with.borrow_mut() = Some(Status::from_os_status(-34018));
    let kc = Keychain::new(&fake);
    for err in [
        kc.read("credentials").unwrap_err(),
        kc.write("credentials", b"x").unwrap_err(),
        kc.delete("credentials").unwrap_err(),
        kc.delete_all().unwrap_err(),
    ] {
        assert_eq!(err.code(), -34018);
        assert!(err.to_string().contains("YADORILINK_CREDENTIAL_STORE=file"), "{err}");
    }
    *fake.fail_with.borrow_mut() = Some(Status::from_os_status(-25293));
    let err = kc.read("credentials").unwrap_err();
    assert!(!err.to_string().contains("YADORILINK_CREDENTIAL_STORE"), "{err}");
}

#[test]
fn os_status_mapping() {
    assert_eq!(Status::from_os_status(-25300), Status::NotFound);
    assert_eq!(Status::from_os_status(-25299), Status::Duplicate);
    assert_eq!(Status::from_os_status(-1), Status::Other(-1));
}

/// The real SecItem path on an iOS simulator. A test binary carries no
/// `keychain-access-groups` entitlement, so the system must refuse: with
/// `errSecMissingEntitlement` (-34018), or with `errSecNotAvailable` (-25291)
/// when the standalone simulator process has no keychain at all. Either has to
/// surface as an error, never as a stored or absent secret; the missing
/// entitlement also names the file-store switch.
#[cfg(all(target_os = "ios", target_abi = "sim"))]
#[test]
fn the_system_keychain_without_the_entitlement_fails_closed() {
    let keychain = Keychain::system();
    let err = keychain.write("simulator-test", b"secret").expect_err("an unentitled write");
    assert!([-34018, -25291].contains(&err.code()), "unexpected status {}", err.code());
    if err.code() == -34018 {
        assert!(err.to_string().contains("YADORILINK_CREDENTIAL_STORE=file"));
    }
    assert!(keychain.read("simulator-test").is_err(), "a read must not report absence");
}
