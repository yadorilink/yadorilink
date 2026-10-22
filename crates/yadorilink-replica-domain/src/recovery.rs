//! Recovery-inventory domain identity: which local recovery journal a
//! decoded (or undecoded) row belongs to.

/// Which local journal a decoded/undecoded recovery-inventory row came
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryDomain {
    Enrollment,
    Membership,
    RoleLoss,
}

impl RecoveryDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryDomain::Enrollment => "enrollment",
            RecoveryDomain::Membership => "membership",
            RecoveryDomain::RoleLoss => "role-loss",
        }
    }

    /// Parses the same strings [`Self::as_str`] produces -- the wire/CLI
    /// value for `--domain`. An unrecognized value (a typo, most likely)
    /// must be rejected explicitly by the caller rather than silently
    /// matching zero rows and being misreported as "operation not found".
    pub fn try_from_str(value: &str) -> Option<Self> {
        match value {
            "enrollment" => Some(RecoveryDomain::Enrollment),
            "membership" => Some(RecoveryDomain::Membership),
            "role-loss" => Some(RecoveryDomain::RoleLoss),
            _ => None,
        }
    }
}

/// A recovery journal row whose contents could not be decoded -- carries
/// only what could be read without trusting the row's own shape, mirroring
/// each domain's own `Invalid*Operation` type.
#[derive(Debug, Clone)]
pub struct InvalidRecoveryOperation {
    pub operation_id: Option<String>,
    pub domain: RecoveryDomain,
    pub raw_state: Option<String>,
    pub detail: String,
}

/// The result of an inventory-only scan (`scan_all_enrollment_operations`/
/// `scan_all_membership_operations`/`scan_all_role_loss_operations`) --
/// distinct from each domain's own production `*Scan` type (whose
/// `Invalid*Operation.operation_id: String` production callers rely on
/// being a real, usable id) because an inventory-only scan can additionally
/// encounter a row whose `operation_id` column itself is not valid TEXT --
/// there is no id to report for such a row, so
/// [`InvalidRecoveryOperation`]'s own `operation_id: Option<String>` is the
/// only shape that can represent it.
#[derive(Debug, Clone)]
pub struct InventoryScanResult<T> {
    pub valid: Vec<T>,
    pub invalid: Vec<InvalidRecoveryOperation>,
}

impl<T> Default for InventoryScanResult<T> {
    fn default() -> Self {
        InventoryScanResult { valid: Vec::new(), invalid: Vec::new() }
    }
}
