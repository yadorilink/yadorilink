//! Track Send CLI commands: `send`, `inbox`, `receive` -- a one-shot P2P
//! file transfer to/from another same-account device, entirely separate
//! from linked-folder sync. See `yadorilink-send`'s own crate doc comment
//! for why.

use yadorilink_client_core::ops::transfers;

use crate::error::CliError;

pub async fn send(source_path: String, target_device: String) -> Result<(), CliError> {
    let result = transfers::send_file(source_path, target_device).await?;
    println!("Offered transfer {}", result.transfer_id);
    for file in &result.files_offered {
        println!("  {file}");
    }
    println!("Total {} bytes", result.total_size);
    Ok(())
}

pub async fn inbox() -> Result<(), CliError> {
    let transfers = transfers::list_inbox().await?;
    if transfers.is_empty() {
        println!("Inbox is empty.");
        return Ok(());
    }
    for transfer in &transfers {
        println!(
            "{}  from {}  {} file(s), {} bytes  [{}]",
            transfer.transfer_id,
            transfer.sender_device_id,
            transfer.files.len(),
            transfer.total_size,
            transfer.status,
        );
        if matches!(transfer.status.as_str(), "failed" | "canceled") {
            println!("    {}", reasons::why_stopped(&transfer.failure));
            println!("    resume with: yadorilink transfer retry {}", transfer.transfer_id);
        }
        for file in &transfer.files {
            println!("    {}  ({} bytes)", file.relative_path, file.size);
        }
    }
    Ok(())
}

pub async fn outbox() -> Result<(), CliError> {
    let sent = transfers::list_sent().await?;
    if sent.is_empty() {
        println!("Nothing has been sent from this device.");
        return Ok(());
    }
    for transfer in &sent {
        println!(
            "{}  to {}  {} file(s), {} bytes  [{}]",
            transfer.transfer_id,
            transfer.target_device_id,
            transfer.files.len(),
            transfer.total_size,
            reasons::sent_status(&transfer.status),
        );
        if !transfer.failure.is_empty() || transfer.status == "declined" {
            println!("    {}", reasons::why_stopped(&transfer.failure));
        }
        if transfer.status == "accepted" || transfer.status == "offered" {
            println!("    stop it with: yadorilink transfer cancel {}", transfer.transfer_id);
        }
        if transfer.can_retry {
            println!("    offer it again with: yadorilink transfer retry {}", transfer.transfer_id);
        }
        for file in &transfer.files {
            println!("    {}  ({} bytes)", file.relative_path, file.size);
        }
    }
    Ok(())
}

pub async fn cancel(transfer_id: String) -> Result<(), CliError> {
    transfers::cancel_transfer(transfer_id.clone()).await?;
    println!("Transfer {transfer_id} stopped. A finished transfer is left as it is; retry a stopped one to start it again.");
    Ok(())
}

pub async fn retry(transfer_id: String) -> Result<(), CliError> {
    match transfers::retry_transfer(transfer_id, transfers::RetryDirection::Any).await? {
        transfers::Retried::Received(result) => {
            println!("Received into {}", result.destination_dir);
            for file in &result.files_received {
                println!("  {file}");
            }
            println!("Total {} bytes", result.bytes_received);
        }
        transfers::Retried::Offered(result) => {
            println!("Offered transfer {} again", result.transfer_id);
            for file in &result.files_offered {
                println!("  {file}");
            }
            println!("Total {} bytes", result.total_size);
        }
    }
    Ok(())
}

/// The CLI's words for a transfer's status and for why it stopped.
mod reasons {
    pub(super) fn sent_status(status: &str) -> &str {
        match status {
            "offered" => "waiting for the device",
            "accepted" => "accepted, waiting for the device to fetch it",
            "completed" => "completed",
            "declined" => "declined",
            "canceled" => "canceled",
            other => other,
        }
    }

    pub(super) fn why_stopped(code: &str) -> &'static str {
        match code {
            "unreachable" => "The other device could not be reached.",
            "declined" => "The other device declined it.",
            "sender_canceled" => "The sending device canceled it.",
            "not_accepted" => {
                "The sending device does not hold it as accepted; ask for it to be sent again."
            }
            "rejected" => "The other device refused it.",
            "verification_failed" => "What arrived did not match what was offered.",
            "stalled" => {
                "The other device stopped fetching it; it can fetch it again, or stop it with transfer cancel."
            }
            "local_storage" => {
                "This device could not store what arrived; check the destination and free space."
            }
            _ => "It stopped before it finished.",
        }
    }
}

pub async fn receive(transfer_id: String, to: Option<String>) -> Result<(), CliError> {
    let result = transfers::receive_transfer(transfer_id, to).await?;
    println!("Received into {}", result.destination_dir);
    for file in &result.files_received {
        println!("  {file}");
    }
    println!("Total {} bytes", result.bytes_received);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::reasons::{sent_status, why_stopped};

    /// Every reason code the daemon lists has its own sentence; only an unknown one falls back.
    #[test]
    fn every_failure_code_has_its_own_sentence() {
        let fallback = why_stopped("something_new");
        for code in [
            "unreachable",
            "declined",
            "sender_canceled",
            "not_accepted",
            "rejected",
            "verification_failed",
            "local_storage",
            "stalled",
        ] {
            assert_ne!(why_stopped(code), fallback, "{code}");
        }
        assert_eq!(why_stopped("interrupted"), fallback);
    }

    #[test]
    fn a_sent_transfers_status_reads_in_words() {
        assert_eq!(sent_status("offered"), "waiting for the device");
        assert_eq!(sent_status("declined"), "declined");
        assert_eq!(sent_status("new"), "new");
    }
}
