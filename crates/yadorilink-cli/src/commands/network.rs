//! `yadorilink network show|sync-on-metered|pause-on-metered`: whether syncing may use a metered
//! connection.

use yadorilink_client_core::ops::network;
use yadorilink_ipc_proto::daemonctl::NetworkPolicy;

use crate::error::CliError;

fn describe(policy: &NetworkPolicy) -> String {
    let setting = if policy.sync_on_metered {
        "Syncing is allowed on a metered connection."
    } else {
        "Syncing pauses on a metered connection."
    };
    if policy.paused_on_metered {
        format!("{setting} It is paused now: this connection is metered.")
    } else {
        setting.to_string()
    }
}

pub async fn show() -> Result<(), CliError> {
    println!("{}", describe(&network::network_policy().await?));
    Ok(())
}

pub async fn set_sync_on_metered(enabled: bool) -> Result<(), CliError> {
    println!("{}", describe(&network::set_sync_on_metered(enabled).await?));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_paused_state_is_named_with_the_way_out() {
        let paused = NetworkPolicy { sync_on_metered: false, cost: 2, paused_on_metered: true };
        assert!(describe(&paused).contains("paused now"));
        let allowed = NetworkPolicy { sync_on_metered: true, cost: 2, paused_on_metered: false };
        assert!(!describe(&allowed).contains("paused now"));
    }
}
