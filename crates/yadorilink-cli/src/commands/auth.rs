//! `yadorilink login`, `yadorilink logout` and `yadorilink
//! forget-local-credentials`.
//!
//! The flows themselves live in `yadorilink_client_core::ops::auth`; this
//! module prints each progress step as the flow reports it, in the order it
//! reports them.

use yadorilink_client_core::ops::auth as ops;
use yadorilink_client_core::wording::{login_event_lines, sign_out_line};

use crate::error::CliError;

/// Enrol this installation and sign it in. `device`: sign in with the
/// device-code grant instead of the loopback redirect.
pub async fn login(device: bool) -> Result<(), CliError> {
    ops::login(device, |event| {
        for line in login_event_lines(&event) {
            println!("{line}");
        }
    })
    .await?;
    Ok(())
}

/// Sign out: revoke this installation's authority, confirm it, and only then
/// destroy the local credential. A revocation that cannot be confirmed keeps
/// the credential and fails, rather than deleting it and claiming success.
pub async fn logout(yes: bool) -> Result<(), CliError> {
    super::confirm_destructive(
        "Sign out and revoke this computer's access? This cannot be undone. Files already on \
         this computer stay on disk.",
        yes,
    )?;
    let kind = ops::sign_out().await?;
    println!("{}", sign_out_line(&kind));
    Ok(())
}

/// Destroy this machine's stored credential WITHOUT revoking anything.
pub async fn forget_local_credentials() -> Result<(), CliError> {
    ops::forget_local_credentials().await?;
    println!("{FORGOT_LOCAL_CREDENTIALS}");
    Ok(())
}

/// Purge this machine's local credential store, for `uninstall.sh --purge-data`.
pub async fn credentials_purge() -> Result<(), CliError> {
    ops::purge_local_credentials().await?;
    println!("Local credential store purged. Nothing was revoked on the server.");
    Ok(())
}

const FORGOT_LOCAL_CREDENTIALS: &str = "Local credentials removed. This computer is still \
                                        authorized on the server -- sign out, or remove this \
                                        device from another one, to revoke it.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forget_local_credentials_line_is_pinned_verbatim() {
        assert_eq!(
            FORGOT_LOCAL_CREDENTIALS,
            "Local credentials removed. This computer is still authorized on the server -- sign \
             out, or remove this device from another one, to revoke it."
        );
    }
}
