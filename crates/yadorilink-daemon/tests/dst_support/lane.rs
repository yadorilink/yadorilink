//! The shared lane knob a
//! scenario's op-count reads so lane 1 ("each scenario x 1 seed, reduced op
//! budget") can shrink the per-run workload without every scenario growing its
//! own env var.
//!
//! The one-seed simulation lane sets `DST_OPS_BUDGET`; a scenario computing how
//! many ops to generate calls `lane::op_budget(default)` instead of hard-coding
//! its default, so lane 1 gets a fast smoke while lane 2 (which does not set
//! the var) keeps the scenario's own default.
/// The per-run op budget: `DST_OPS_BUDGET` if the current lane set it, else the
/// scenario's own `default`. Values below 1 are clamped to 1 (a zero-op run
/// tests nothing).
pub fn op_budget(default: usize) -> usize {
    match std::env::var("DST_OPS_BUDGET").ok().and_then(|s| s.parse::<usize>().ok()) {
        Some(n) => n.max(1),
        None => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These mutate a process-global env var; keep them in one test so they
    // cannot interleave with each other under the test harness's threads.
    #[test]
    fn op_budget_prefers_env_then_default_and_clamps() {
        // Unset: the scenario default wins.
        std::env::remove_var("DST_OPS_BUDGET");
        assert_eq!(op_budget(15), 15);

        // Set: the lane budget wins.
        std::env::set_var("DST_OPS_BUDGET", "3");
        assert_eq!(op_budget(15), 3);

        // Zero is clamped to a still-meaningful single op.
        std::env::set_var("DST_OPS_BUDGET", "0");
        assert_eq!(op_budget(15), 1);

        // Garbage falls back to the default rather than panicking.
        std::env::set_var("DST_OPS_BUDGET", "not-a-number");
        assert_eq!(op_budget(15), 15);

        std::env::remove_var("DST_OPS_BUDGET");
    }
}
