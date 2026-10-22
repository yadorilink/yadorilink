//! The one generation of every native wire object.
//!
//! Signed deltas (wire, header and body encodings), checkpoints, seal
//! evidence, recovery bundles and protocol-5 envelopes all open with a domain
//! tag: a seven-byte kind followed by this generation byte. The generation is
//! bumped for all of them at once when any encoding changes; there is no
//! migration ladder, and an object of another generation is refused outright,
//! never reinterpreted.

use crate::codec::ChangeError;

/// The generation byte closing every native domain tag.
pub const NATIVE_PROTOCOL_GENERATION: u8 = 9;

/// The length of the kind prefix of a native domain tag.
pub const NATIVE_TAG_PREFIX_LEN: usize = 7;

/// The domain tag of the native object kind `kind` at the current generation.
pub const fn native_domain_tag(
    kind: &[u8; NATIVE_TAG_PREFIX_LEN],
) -> [u8; NATIVE_TAG_PREFIX_LEN + 1] {
    let mut tag = [0u8; NATIVE_TAG_PREFIX_LEN + 1];
    let mut i = 0;
    while i < NATIVE_TAG_PREFIX_LEN {
        tag[i] = kind[i];
        i += 1;
    }
    tag[NATIVE_TAG_PREFIX_LEN] = NATIVE_PROTOCOL_GENERATION;
    tag
}

/// Refuses `tag` unless it is `expected`: a different kind is a bad tag, the same
/// kind at another generation is an unsupported generation.
pub fn check_native_tag(tag: &[u8], expected: &[u8; 8], what: &str) -> Result<(), ChangeError> {
    if tag.len() != expected.len()
        || tag[..NATIVE_TAG_PREFIX_LEN] != expected[..NATIVE_TAG_PREFIX_LEN]
    {
        return Err(ChangeError::Encoding(format!("bad {what} domain tag")));
    }
    if tag[NATIVE_TAG_PREFIX_LEN] != expected[NATIVE_TAG_PREFIX_LEN] {
        return Err(ChangeError::UnsupportedGeneration {
            theirs: tag[NATIVE_TAG_PREFIX_LEN],
            ours: expected[NATIVE_TAG_PREFIX_LEN],
        });
    }
    Ok(())
}
