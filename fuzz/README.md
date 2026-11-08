# Fuzzing the parsers of untrusted input

cargo-fuzz (libFuzzer) targets for what a peer, the coordination service or a person can hand the
daemon as bytes. Not a member of the main workspace: nothing here changes the normal build.

| Target | Parser |
|---|---|
| `protocol5_message`, `protocol5_proof` | native wire envelope and Merkle proof |
| `authorization_checkpoint` | checkpoint and Merkle-proof decoders |
| `native_delta` | signed delta (structure, not signature) |
| `author_closure`, `native_checkpoint`, `native_checkpoint_seal`, `native_row_identity` | the other signed native objects |
| `service_rpc` | service request/response frames |
| `block_headers` | block-stream request/response headers (protobuf) |
| `hello` | the peer hello frame |
| `ignore_rules` | ignore-file text |
| `policy_log` | the policy log JSON as the service delivers it, then its chain verification (daemon-linked: long build) |
| `send_link_code` | Send link code parsing and the sealed file list (daemon-linked) |

The daemon entry points exist only under `cfg(fuzzing)` (`change_policy::fuzz_policy_log`,
`coordination_client::fuzz_send_code`).

```sh
rustup toolchain install nightly && cargo install cargo-fuzz
fuzz/run.sh 600 native_delta      # one target, 10 minutes (from any directory)
fuzz/run.sh 120                   # every target, 2 minutes each
fuzz/smoke.sh                     # the decoder targets, 15 s each, on the seed corpus
```

Run heavy sessions on a dedicated machine, not on a laptop. A crash is left in `artifacts/<target>/`:
reduce it (`cargo +nightly fuzz tmin <target> <file>`), fix the decoder so it returns an error, and
add the bytes as a regression test in the crate's own tests. `corpus/<target>/` holds the committed
seeds (tag-prefixed shells and small valid shapes); what the fuzzer adds stays untracked.

## Results so far (2026-11-05, Linux, nightly, libFuzzer, max_len 64 KiB)

| Run | Targets | Executions | Crashes |
|---|---|---|---|
| 150 s each | the 11 decoder targets | 12 to 50 million per target | 0 |
| 300 s each | `policy_log`, `send_link_code` | 16.5 and 15.5 million | 0 |
