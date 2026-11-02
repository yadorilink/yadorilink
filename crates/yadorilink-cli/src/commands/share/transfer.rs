//! `yadorilink share transfer ...`: handing a folder's primary ownership to another person.
//!
//! The primary owner offers to a member device of another account; that account accepts or
//! declines, or the primary cancels. Each command calls the typed operation in
//! `yadorilink_client_core::ops::primary_transfer` and prints what it returned. The line builders
//! are pure, so every line is pinned by a unit test. A refusal by the service exits with
//! `EXIT_PRIMARY_TRANSFER_REFUSED`; the reason is typed, never parsed from text.

use std::path::Path;

use yadorilink_client_core::coordination::http_client::CoordinationAccess;
use yadorilink_client_core::ops::primary_transfer::{
    self as transfers, PrimaryTransfer, PrimaryTransferAccepted, SettleStep, TransferDirection,
};
use yadorilink_client_core::ops::shares as shares_ops;
use yadorilink_client_core::wording::short_device_id;

use super::format_expiry;
use crate::error::CliError;

/// `share transfer offer <group> <device>`.
pub async fn offer(group_name: String, device_id: String) -> Result<(), CliError> {
    let group_id = shares_ops::resolve_group_name(&group_name).await?;
    let offer = transfers::offer(&group_id, &device_id).await?;
    for line in offer_lines(&offer) {
        println!("{line}");
    }
    Ok(())
}

/// `share transfer cancel <group-or-offer>`: withdraws the offer you made.
pub async fn cancel(selector: String) -> Result<(), CliError> {
    let (auth, dir) = transfers::process_context().await?;
    println!("{}", cancel_line(&auth, &dir, &selector).await?);
    Ok(())
}

/// `share transfer accept <group-or-offer>`: takes over the folder offered to you.
pub async fn accept(selector: String) -> Result<(), CliError> {
    let (auth, dir) = transfers::process_context().await?;
    println!("{}", accept_line(&auth, &dir, &selector).await?);
    Ok(())
}

/// `share transfer decline <group-or-offer>`: turns down the folder offered to you.
pub async fn decline(selector: String) -> Result<(), CliError> {
    let (auth, dir) = transfers::process_context().await?;
    println!("{}", decline_line(&auth, &dir, &selector).await?);
    Ok(())
}

async fn cancel_line(
    auth: &CoordinationAccess,
    dir: &Path,
    selector: &str,
) -> Result<String, CliError> {
    let offer = select_in(auth, dir, SettleStep::Cancel, selector).await?;
    let done = transfers::cancel_in(auth, dir, &offer.group_id, &offer.transfer_id).await?;
    Ok(cancelled_line(&done))
}

async fn accept_line(
    auth: &CoordinationAccess,
    dir: &Path,
    selector: &str,
) -> Result<String, CliError> {
    let offer = select_in(auth, dir, SettleStep::Accept, selector).await?;
    let done = transfers::accept_in(auth, dir, &offer.group_id, &offer.transfer_id).await?;
    Ok(accepted_line(&offer.group_name, &done))
}

async fn decline_line(
    auth: &CoordinationAccess,
    dir: &Path,
    selector: &str,
) -> Result<String, CliError> {
    let offer = select_in(auth, dir, SettleStep::Decline, selector).await?;
    let done = transfers::decline_in(auth, dir, &offer.group_id, &offer.transfer_id).await?;
    Ok(declined_line(&done))
}

/// The offer `selector` names: a listed one, or an unanswered call to repeat.
async fn select_in(
    auth: &CoordinationAccess,
    dir: &Path,
    step: SettleStep,
    selector: &str,
) -> Result<transfers::SelectedOffer, CliError> {
    Ok(transfers::select_offer_in(auth, dir, step, selector).await?)
}

/// `share transfer list`: the pending offers you made and were made.
pub async fn list() -> Result<(), CliError> {
    for line in list_lines(&transfers::list().await?) {
        println!("{line}");
    }
    Ok(())
}

fn offer_lines(offer: &PrimaryTransfer) -> Vec<String> {
    vec![
        format!(
            "Offered ownership of {} to the account of device {}",
            offer.group_name,
            short_device_id(&offer.to_device_id)
        ),
        format!("  offer id: {}", offer.transfer_id),
        format!("  expires in: {}", format_expiry(offer.expires_at)),
        format!(
            "  Nothing changes until they accept. Withdraw it with `yadorilink share transfer \
             cancel {}`.",
            offer.group_name
        ),
    ]
}

fn cancelled_line(offer: &PrimaryTransfer) -> String {
    format!("Withdrew the ownership offer for {}", offer.group_name)
}

fn declined_line(offer: &PrimaryTransfer) -> String {
    format!("Declined the ownership offer for {}", offer.group_name)
}

fn accepted_line(group_name: &str, accepted: &PrimaryTransferAccepted) -> String {
    format!(
        "You are now the primary owner of {group_name} (membership generation {})",
        accepted.membership_generation
    )
}

fn list_lines(all: &[PrimaryTransfer]) -> Vec<String> {
    if all.is_empty() {
        return vec!["No pending ownership offers.".to_owned()];
    }
    all.iter()
        .map(|t| {
            let (arrow, who) = match t.direction {
                TransferDirection::Outgoing => ("offered to", "device"),
                TransferDirection::Incoming => ("offered to you (via", "device"),
                TransferDirection::Unrecognized => ("offered (", "device"),
            };
            let tail = if t.direction == TransferDirection::Outgoing { "" } else { ")" };
            format!(
                "{}  {}  {arrow} {who} {}{tail}  expires in {}  [{}]",
                t.transfer_id,
                t.group_name,
                short_device_id(&t.to_device_id),
                format_expiry(t.expires_at),
                direction_word(t.direction),
            )
        })
        .collect()
}

fn direction_word(direction: TransferDirection) -> &'static str {
    match direction {
        TransferDirection::Outgoing => "outgoing",
        TransferDirection::Incoming => "incoming",
        TransferDirection::Unrecognized => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use yadorilink_client_core::PrimaryTransferRefusal;

    use super::*;

    fn transfer(id: &str, group: &str, direction: TransferDirection) -> PrimaryTransfer {
        PrimaryTransfer {
            transfer_id: id.into(),
            group_id: format!("gid-{group}"),
            group_name: group.into(),
            direction,
            status: "pending".into(),
            to_device_id: "device-abcdefgh-1234".into(),
            created_at: 0,
            expires_at: 0,
        }
    }

    #[test]
    fn an_empty_list_says_so_and_a_refusal_has_its_own_exit_code() {
        assert_eq!(list_lines(&[]), vec!["No pending ownership offers.".to_owned()]);
        let error = CliError::PrimaryTransferRefused(PrimaryTransferRefusal::NotPrimary);
        assert_eq!(error.exit_code(), crate::error::EXIT_PRIMARY_TRANSFER_REFUSED);
        assert_eq!(error.to_string(), "only the folder's primary owner can do this");
        assert!(!error.is_reportable());
    }

    #[test]
    fn lines_name_the_folder_and_never_the_other_account() {
        let offer = transfer("t1", "photos", TransferDirection::Outgoing);
        let lines = offer_lines(&offer).join("\n");
        assert!(lines.contains("photos") && lines.contains("device-a") && lines.contains("t1"));
        assert!(lines.contains("share transfer cancel photos"));
        let listed = list_lines(&[offer, transfer("t2", "docs", TransferDirection::Incoming)]);
        assert!(listed[0].contains("offered to device device-a") && listed[0].contains("outgoing"));
        assert!(listed[1].contains("offered to you") && listed[1].contains("incoming"));
        assert_eq!(
            accepted_line(
                "photos",
                &PrimaryTransferAccepted {
                    transfer_id: "t".into(),
                    group_id: "g".into(),
                    membership_generation: 7
                }
            ),
            "You are now the primary owner of photos (membership generation 7)"
        );
    }

    /// The service completed an accept and the reply was lost: the offer is no longer listed, and
    /// the next `share transfer accept` must still repeat the call under its saved operation id
    /// (the service replays the original outcome) rather than report the offer as not found.
    #[tokio::test]
    async fn accept_after_a_lost_reply_replays_the_saved_operation_without_a_listed_offer() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let state = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;
        let auth = CoordinationAccess::new(
            yadorilink_fapi_client::test_support::offline_auth(),
            server.uri(),
        );
        let route = "/shares/groups/g-12345678/primary-transfer/accept";
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transferId": "tr-12345678", "groupId": "g-12345678", "membershipGeneration": 7
            })))
            .mount(&server)
            .await;
        // Listed while the offer is pending, then gone once the service has done the accept.
        Mock::given(method("GET"))
            .and(path("/shares/primary-transfers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "transfers": [{
                    "transferId": "tr-12345678", "groupId": "g-12345678", "groupName": "photos",
                    "direction": "incoming", "status": "pending", "toDeviceId": "dev-target-1",
                    "createdAt": 1_700_000_000, "expiresAt": 1_700_604_800
                }]
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/shares/primary-transfers"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "transfers": [] })),
            )
            .mount(&server)
            .await;

        let first = accept_line(&auth, state.path(), "photos").await;
        assert!(first.is_err(), "the reply was lost: {first:?}");
        let second = accept_line(&auth, state.path(), "g-12345678").await.unwrap();
        assert!(second.contains("membership generation 7"), "{second}");

        let ids: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == "POST")
            .map(|r| {
                let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
                body["operationId"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], ids[1], "the repeat must carry the saved operation id");
    }
}
