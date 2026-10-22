#![cfg(test)]

use super::compress_block;

#[test]
#[ignore]
fn bytes_on_wire_and_cost_source_tree_vs_media() {
    // "source tree" stand-in: many small, highly repetitive Rust-like
    // source files concatenated into one corpus — representative of
    // source trees, documents, logs, and DB dumps as the target
    // workload shape.
    let mut source_tree = Vec::new();
    for i in 0..2000 {
        source_tree.extend_from_slice(
            format!(
                "use std::fmt;\n\npub struct Item{i} {{\n    pub id: u64,\n    pub \
                 name: String,\n}}\n\nimpl fmt::Display for Item{i} {{\n    fn fmt(&self, \
                 f: &mut fmt::Formatter<'_>) -> fmt::Result {{\n        write!(f, \
                 \"Item{{}}\", self.id)\n    }}\n}}\n\n"
            )
            .as_bytes(),
        );
    }

    // "media" stand-in: high-entropy bytes — the shape an
    // already-compressed photo/video/archive has on the wire, sized to
    // match the source-tree corpus for a fair side-by-side comparison.
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    let media: Vec<u8> = (0..source_tree.len())
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        })
        .collect();

    for (label, corpus) in
        [("source-tree-like text", &source_tree), ("media-like (incompressible)", &media)]
    {
        let start = std::time::Instant::now();
        let (out, compression) = compress_block(corpus);
        let elapsed = start.elapsed();
        let ratio = 100.0 * out.len() as f64 / corpus.len() as f64;
        println!(
            "{label}: raw={} bytes, wire={} bytes ({ratio:.1}% of raw), \
             compression={compression:?}, compress_block took {elapsed:?}",
            corpus.len(),
            out.len(),
        );
    }
}
