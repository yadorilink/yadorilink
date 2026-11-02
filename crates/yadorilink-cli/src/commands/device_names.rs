//! Device ids as people know them, for the commands that print devices.

/// Device ids as people know them: this device, a device on the account by its
/// name, anything else as "another device". Never a raw id. Names come from the
/// account's device list when it can be read; nothing here fails a command.
#[derive(Debug, Default)]
pub(crate) struct DeviceNames {
    pub(crate) own_device_id: Option<String>,
    pub(crate) names: std::collections::HashMap<String, String>,
    /// The names come from an earlier list because the account could not be asked now: a device
    /// may since have been renamed or removed, so every name is said to be the last known one.
    pub(crate) stale: bool,
}

/// How long a fetched device list is trusted before the account is asked again.
const NAME_CACHE_TTL_SECS: i64 = 300;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct NameCache {
    fetched_unix: i64,
    names: std::collections::HashMap<String, String>,
}

impl NameCache {
    fn is_fresh(&self, now_unix: i64) -> bool {
        (0..NAME_CACHE_TTL_SECS).contains(&(now_unix - self.fetched_unix))
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn name_cache_path() -> Option<std::path::PathBuf> {
    yadorilink_client_core::coordination::device_config::config_dir()
        .ok()
        .map(|dir| dir.join("device-names.json"))
}

/// A missing, torn or unreadable file is no cache, never an error.
fn read_name_cache(path: &std::path::Path) -> Option<NameCache> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Best effort and not durable: it is only a cache, and a lost write costs one lookup.
fn write_name_cache(path: &std::path::Path, cache: &NameCache) {
    let Ok(bytes) = serde_json::to_vec(cache) else { return };
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    if std::fs::write(&tmp, bytes).is_ok() && std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

impl DeviceNames {
    pub(crate) async fn load() -> Self {
        Self::load_with(&[]).await
    }

    /// [`Self::load`] that skips the round trip while a list fetched in the last few minutes
    /// already names every device in `wanted` (a device it does not know is a reason to ask).
    pub(crate) async fn load_cached(wanted: &[&str]) -> Self {
        Self::load_with(wanted).await
    }

    async fn load_with(wanted: &[&str]) -> Self {
        // Names are a nicety on top of local results: an offline or slow
        // coordination service costs at most this long, then ids read as
        // "another device".
        const NAME_LOOKUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
        let own_device_id = yadorilink_client_core::ops::shares::own_device_id();
        // `status` is asked while a large sync is running, once a second by a script or a tray,
        // and a name is not worth a round trip to the coordination service each time (it took
        // the whole 2 s budget whenever that service was busy): the last list is kept beside the
        // other local state and trusted for a few minutes.
        let cache = name_cache_path();
        let cached = cache.as_deref().and_then(read_name_cache);
        // `load()` (no devices named) always asks: it has no way to know the list is complete.
        if let Some(cached) = cached.as_ref().filter(|c| {
            !wanted.is_empty()
                && c.is_fresh(now_unix())
                && wanted
                    .iter()
                    .all(|id| c.names.contains_key(*id) || own_device_id.as_deref() == Some(*id))
        }) {
            return Self { own_device_id, names: cached.names.clone(), stale: false };
        }
        let fetched = tokio::time::timeout(
            NAME_LOOKUP_BUDGET,
            yadorilink_client_core::ops::devices::list_devices(),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .map(|devices| {
            devices
                .into_iter()
                .map(|d| (d.device_id, d.device_name))
                .collect::<std::collections::HashMap<_, _>>()
        });
        let (names, stale) = match fetched {
            Some(names) => {
                if let Some(path) = cache.as_deref() {
                    write_name_cache(
                        path,
                        &NameCache { fetched_unix: now_unix(), names: names.clone() },
                    );
                }
                (names, false)
            }
            // The service could not be asked. `load()` (nothing to skip a lookup for) shows no
            // names rather than possibly obsolete ones; the cached form shows the old ones,
            // marked as such.
            None if wanted.is_empty() => (Default::default(), false),
            None => cached.map_or((Default::default(), false), |c| (c.names, true)),
        };
        Self { own_device_id, names, stale }
    }

    pub(crate) fn label(&self, device_id: &str) -> String {
        if device_id.is_empty() {
            return "an unknown device".to_string();
        }
        if self.own_device_id.as_deref() == Some(device_id) {
            return "this device".to_string();
        }
        match self.names.get(device_id) {
            Some(name) if !name.trim().is_empty() && self.stale => {
                format!("{name} (last known name)")
            }
            Some(name) if !name.trim().is_empty() => name.clone(),
            _ => "another device".to_string(),
        }
    }

    /// Whether `device_id` is this device.
    pub(crate) fn is_own(&self, device_id: &str) -> bool {
        self.own_device_id.as_deref() == Some(device_id)
    }

    /// The name the account gives `device_id`, when the device list could be read and has one.
    pub(crate) fn name_of(&self, device_id: &str) -> Option<String> {
        self.names.get(device_id).filter(|name| !name.trim().is_empty()).map(|name| {
            if self.stale {
                format!("{name} (last known name)")
            } else {
                name.clone()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(fetched_unix: i64) -> NameCache {
        NameCache { fetched_unix, names: [("d1".to_string(), "Laptop".to_string())].into() }
    }

    #[test]
    fn a_list_is_trusted_for_a_few_minutes_and_not_beyond_nor_from_the_future() {
        let c = cache(1_000);
        assert!(c.is_fresh(1_000));
        assert!(c.is_fresh(1_000 + NAME_CACHE_TTL_SECS - 1));
        assert!(!c.is_fresh(1_000 + NAME_CACHE_TTL_SECS));
        // A clock set back must not keep an old list alive.
        assert!(!c.is_fresh(999));
    }

    #[test]
    fn a_name_from_an_earlier_list_says_so_and_a_fresh_one_does_not() {
        let mut names = DeviceNames {
            own_device_id: None,
            names: [("d1".to_string(), "Laptop".to_string())].into(),
            stale: false,
        };
        assert_eq!(names.label("d1"), "Laptop");
        assert_eq!(names.name_of("d1").as_deref(), Some("Laptop"));
        names.stale = true;
        assert_eq!(names.label("d1"), "Laptop (last known name)");
        assert_eq!(names.name_of("d1").as_deref(), Some("Laptop (last known name)"));
        assert_eq!(names.label("d2"), "another device");
    }

    #[test]
    fn the_cache_round_trips_and_a_torn_file_is_no_cache() {
        let dir = std::env::temp_dir().join(format!("yl-names-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device-names.json");
        assert!(read_name_cache(&path).is_none());
        write_name_cache(&path, &cache(42));
        let read = read_name_cache(&path).unwrap();
        assert_eq!(
            (read.fetched_unix, read.names.get("d1").map(String::as_str)),
            (42, Some("Laptop"))
        );
        std::fs::write(&path, b"{\"fetched_unix\": 4").unwrap();
        assert!(read_name_cache(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
