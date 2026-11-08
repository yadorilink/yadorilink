//! The signed-in account's email, sign-in provider and display name, read once per sign-in and kept.
//!
//! The status API is polled and must work offline, so the coordination read is made at most once
//! per `client_id` (each sign-in mints a fresh one, so an id names exactly one account and another
//! sign-in never reads this memo). A failed read is not retried until [`RETRY_AFTER`] has passed.

use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::CoreError;

/// How long a failed read is not retried: a status poll must not become a coordination request
/// each time while the service is unreachable.
const RETRY_AFTER: Duration = Duration::from_secs(60);

/// What the account-state read says about the account itself (all informational, all optional).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountInfo {
    /// The contact address; `None` when the provider gave none.
    pub email: Option<String>,
    /// `"google"` or `"apple"`; `None` for a service that does not say (an older one).
    pub sign_in_provider: Option<String>,
    /// The name the provider delivered at the first sign-in (Apple), if any.
    pub display_name: Option<String>,
}

enum Memo {
    Known { client_id: String, info: AccountInfo },
    Failed { client_id: String, at: Instant },
}

/// One memo per engine (or per process, for the desktop client).
pub struct AccountEmailMemo(Mutex<Option<Memo>>);

impl AccountEmailMemo {
    #[must_use]
    pub const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// The account info of the account `client_id` belongs to: the kept answer, else `fetch`'s.
    /// Empty when it cannot be read now.
    pub async fn read(
        &self,
        client_id: &str,
        fetch: impl Future<Output = Result<AccountInfo, CoreError>>,
    ) -> AccountInfo {
        {
            let memo = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            match memo.as_ref() {
                Some(Memo::Known { client_id: id, info }) if id == client_id => {
                    return info.clone();
                }
                Some(Memo::Failed { client_id: id, at })
                    if id == client_id && at.elapsed() < RETRY_AFTER =>
                {
                    return AccountInfo::default();
                }
                _ => {}
            }
        }
        let read = fetch.await;
        let mut memo = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match read {
            Ok(info) => {
                *memo = Some(Memo::Known { client_id: client_id.to_owned(), info: info.clone() });
                info
            }
            Err(_) => {
                *memo = Some(Memo::Failed { client_id: client_id.to_owned(), at: Instant::now() });
                AccountInfo::default()
            }
        }
    }
}

impl Default for AccountEmailMemo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn a_read_is_made_once_per_client_id() {
        let memo = AccountEmailMemo::new();
        let calls = AtomicU32::new(0);
        let fetch = |email: &'static str| {
            let calls = &calls;
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(AccountInfo {
                    email: Some(email.to_owned()),
                    sign_in_provider: Some("apple".to_owned()),
                    display_name: None,
                })
            }
        };
        let first = memo.read("c1", fetch("a@x")).await;
        assert_eq!(first.email.as_deref(), Some("a@x"));
        assert_eq!(first.sign_in_provider.as_deref(), Some("apple"));
        assert_eq!(memo.read("c1", fetch("other")).await.email.as_deref(), Some("a@x"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // another sign-in is another client id and never reads the first one's answer
        assert_eq!(memo.read("c2", fetch("b@x")).await.email.as_deref(), Some("b@x"));
    }

    #[tokio::test]
    async fn a_failed_read_is_not_repeated_at_once_and_not_kept_as_an_answer() {
        let memo = AccountEmailMemo::new();
        let failed = memo.read("c1", async { Err(CoreError::NotLoggedIn) }).await;
        assert_eq!(failed, AccountInfo::default());
        let calls = AtomicU32::new(0);
        let again = memo
            .read("c1", async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(AccountInfo { email: Some("a@x".to_owned()), ..AccountInfo::default() })
            })
            .await;
        assert_eq!((again, calls.load(Ordering::SeqCst)), (AccountInfo::default(), 0));
    }
}
