#!/usr/bin/env python3
"""Keep the embedded host's engine free of the desktop process model.

`yadorilink-daemon` built without its `process-model` feature is the engine an embedding host
(the mobile apps) links. This guard checks, on the source tree alone, the declarations that
keep that build clean:

1. Every module the process model owns is declared `#[cfg(feature = "process-model")]` in
   the daemon's `lib.rs`. `shell_ipc` and `shell_context` are NOT in that list: the provider
   handlers (`provider_apply`, `provider_enumerate`, `provider_materialize`,
   `handle_connection`) live in `shell_ipc` and are the engine's provider surface, so the
   module stays compiled; only its transports and client are process-model code.
2. The `shell_ipc` transports and client are gated, and its provider handlers are not.
3. `notify` is optional in `yadorilink-filesystem-sync` behind `os-watch`, which the daemon's
   `process-model` turns on; the daemon and `yadorilink-local-capture` depend on that crate
   without default features; the daemon has no direct `notify` dependency.
4. The workspace `tokio` does not enable `signal` or `process`; `process-model` does.
5. The embedded host depends on the daemon without default features.
6. The engine finds its state directory from `DaemonState::config_dir` (set at start), not from
   the process environment: outside the files below, no daemon source calls
   `device_config::config_dir()` or `state_dir::state_dir()` or names `YADORILINK_CONFIG_DIR`.
7. The engine's credential settings (`CredentialConfig`: store backend, device-key keyring
   mirror, Authorization Server address) are resolved once by the composition root (`app.rs`)
   or given by the embedding host: no other daemon source names the variables that select
   them or calls the environment mappings (`Backend::from_env`, `KeyMirror::from_env`).
8. The daemon reads no process environment outside its entry point and composition root, and
   every other library crate is held to a reasoned allow-list: that is
   `check-engine-env-reads.py` (the tuning switches are fields of `EngineTuning`, mapped once by
   `DaemonConfig::from_env`).

9. The mobile binding (`yadorilink-mobile-ffi`) reaches the engine only through the embedded
   host: it does not depend on the daemon or the desktop client layer directly (so it cannot
   bring the process model or the control-socket facade into the iOS library), and it builds
   a static library only.

The compiled half (dependency tree and symbols of the built host) is
`.github/ci/embedded-host-surface.sh`.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Modules owned by the desktop process model: gated in the daemon's lib.rs.
PROCESS_MODEL_MODULES = [
    "app",
    "app_group",
    "control_socket",
    "diagnostics_ipc",
    "exe_replaced",
    "exe_watch",
    "log_roll",
    "malloc_arenas",
    "nas_admin",
    "nas_admin_bridge",
    "reporting_ipc",
    "send_transfer",
    "update",
    "update_ipc",
]
# Compiled in the embedded build, whatever their names suggest.
ENGINE_MODULES = ["shell_ipc", "shell_context", "shell_status", "supervise", "resource_lock"]
SHELL_IPC_TRANSPORTS = ["client", "unix_transport", "windows_transport"]
SHELL_IPC_PROVIDER_FILES = ["provider_apply", "provider_enumerate", "provider_materialize"]
PM = 'feature = "process-model"'
GATE = f"#[cfg({PM})]"

# Daemon files that may still resolve the state directory from the environment: the desktop
# composition root and control socket (one process, one directory), the resolver itself, the
# default constructor tests use, the Windows-only sync root record and the default reporting dir.
ENV_STATE_DIR_ALLOWED = {
    "app.rs",
    "device_config.rs",
    "daemon_state.rs",
}
ENV_STATE_DIR_PATTERN = re.compile(
    r"device_config::config_dir\(\)|state_dir::state_dir\(\)|YADORILINK_CONFIG_DIR"
)


# The only daemon source that may name the credential settings' variables or map them.
CREDENTIAL_ENV_ALLOWED = {"app.rs"}
CREDENTIAL_ENV_PATTERN = re.compile(
    r"YADORILINK_CREDENTIAL_STORE|YADORILINK_CREDENTIAL_FILE|YADORILINK_DISABLE_OS_KEYRING"
    r"|YADORILINK_AUTH_SERVER_ADDR|store::(?:STORE_VAR|FILE_VAR)"
    r"|Backend::from_env|KeyMirror::from_env"
)


def module_gates(text: str) -> dict[str, bool]:
    """Maps each `mod` declaration to whether it carries the process-model gate."""
    gates: dict[str, bool] = {}
    attrs: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#[") or s.startswith("///") or s.startswith("//"):
            attrs.append(s)
            continue
        m = re.match(r"(?:pub(?:\([a-z]+\))? )?mod (\w+)\b", s)
        if m:
            gates[m.group(1)] = any(PM in a for a in attrs if a.startswith("#[cfg("))
        attrs = []
    return gates


def check_tree(root: Path) -> list[str]:
    errors: list[str] = []
    daemon = root / "crates/yadorilink-daemon"
    lib = (daemon / "src/lib.rs").read_text(encoding="utf-8")
    gates = module_gates(lib)
    for name in PROCESS_MODEL_MODULES:
        if name not in gates:
            errors.append(f"daemon lib.rs: module `{name}` is not declared (update the guard)")
        elif not gates[name]:
            errors.append(f"daemon lib.rs: process-model module `{name}` must be {GATE}")
    for name in ENGINE_MODULES:
        if gates.get(name):
            errors.append(
                f"daemon lib.rs: `{name}` must stay compiled in the embedded build "
                "(it carries the provider surface or engine plumbing)"
            )

    shell_ipc = (daemon / "src/shell_ipc.rs").read_text(encoding="utf-8")
    inner = module_gates(shell_ipc)
    for name in SHELL_IPC_TRANSPORTS:
        if name not in inner:
            errors.append(f"shell_ipc.rs: module `{name}` is not declared (update the guard)")
        elif not inner[name]:
            errors.append(f"shell_ipc.rs: transport module `{name}` must be {GATE}")
    for name in SHELL_IPC_PROVIDER_FILES:
        if inner.get(name):
            errors.append(f"shell_ipc.rs: provider module `{name}` must not be gated")
        elif name not in inner:
            errors.append(f"shell_ipc.rs: provider module `{name}` is missing")

    dmanifest = (daemon / "Cargo.toml").read_text(encoding="utf-8")
    pm = re.search(r"^process-model\s*=\s*\[(.*?)\]", dmanifest, re.S | re.M)
    pm_items = pm.group(1) if pm else ""
    for needed in ["yadorilink-filesystem-sync/os-watch", "tokio/signal", "tokio/process"]:
        if f'"{needed}"' not in pm_items:
            errors.append(f"daemon Cargo.toml: process-model must enable {needed}")
    if re.search(r"^notify\s*=", dmanifest, re.M):
        errors.append("daemon Cargo.toml: no direct notify dependency (the watcher is os-watch)")
    for crate in ["yadorilink-daemon", "yadorilink-local-capture"]:
        text = (root / "crates" / crate / "Cargo.toml").read_text(encoding="utf-8")
        dep = re.search(r"^yadorilink-filesystem-sync\s*=\s*\{([^}]*)\}", text, re.M)
        if not dep or "default-features = false" not in dep.group(1):
            errors.append(f"{crate} Cargo.toml: filesystem-sync needs default-features = false")
    fs_manifest = (root / "crates/yadorilink-filesystem-sync/Cargo.toml").read_text(encoding="utf-8")
    if not re.search(r"^notify\s*=\s*\{[^}]*optional = true", fs_manifest, re.M):
        errors.append("filesystem-sync Cargo.toml: notify must be optional")
    if not re.search(r'^os-watch\s*=\s*\["dep:notify"\]', fs_manifest, re.M):
        errors.append("filesystem-sync Cargo.toml: feature os-watch must be [\"dep:notify\"]")

    ws = (root / "Cargo.toml").read_text(encoding="utf-8")
    tok = re.search(r"^tokio\s*=\s*\{(.*?)\n?\}", ws, re.S | re.M)
    feats = tok.group(1) if tok else ""
    if not tok or "default-features = false" not in feats:
        errors.append("workspace Cargo.toml: tokio must disable default features")
    for banned in ["signal", "process", "full"]:
        if f'"{banned}"' in feats:
            errors.append(f"workspace Cargo.toml: tokio must not enable `{banned}`")

    host = (root / "crates/yadorilink-embedded-host/Cargo.toml").read_text(encoding="utf-8")
    dep = re.search(r"^yadorilink-daemon\s*=\s*\{([^}]*)\}", host, re.M)
    if not dep or "default-features = false" not in dep.group(1):
        errors.append("embedded-host Cargo.toml: daemon needs default-features = false")
    errors += check_env_state_dir(daemon / "src")
    errors += check_env_reads(daemon / "src")
    errors += check_mobile_ffi(root)
    return errors


MOBILE_FFI_FORBIDDEN_DEPS = ["yadorilink-daemon", "yadorilink-client-core", "yadorilink-client-ffi"]


def check_mobile_ffi(root: Path) -> list[str]:
    manifest = (root / "crates/yadorilink-mobile-ffi/Cargo.toml").read_text(encoding="utf-8")
    errors: list[str] = []
    section = re.search(r"^\[dependencies\]\n(.*?)(?=^\[|\Z)", manifest, re.S | re.M)
    deps = section.group(1) if section else ""
    if not re.search(r"^yadorilink-embedded-host\s*=", deps, re.M):
        errors.append("mobile-ffi Cargo.toml: must depend on yadorilink-embedded-host")
    for banned in MOBILE_FFI_FORBIDDEN_DEPS:
        if re.search(rf"^{banned}\s*=", deps, re.M):
            errors.append(f"mobile-ffi Cargo.toml: must not depend on {banned}; go through the embedded host")
    crate_type = re.search(r"^crate-type\s*=\s*\[(.*?)\]", manifest, re.S | re.M)
    types = crate_type.group(1) if crate_type else ""
    if '"staticlib"' not in types or '"cdylib"' in types:
        errors.append('mobile-ffi Cargo.toml: crate-type must include "staticlib" and not "cdylib"')
    return errors


def check_env_state_dir(src: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(src.rglob("*.rs")):
        rel = path.relative_to(src).as_posix()
        if rel in ENV_STATE_DIR_ALLOWED or "test" in rel:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("//"):
                continue
            if ENV_STATE_DIR_PATTERN.search(line):
                errors.append(
                    f"daemon {rel}:{number}: reads the state directory from the environment; "
                    "use DaemonState::config_dir"
                )
    return errors


def check_env_reads(src: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(src.rglob("*.rs")):
        rel = path.relative_to(src).as_posix()
        if "test" in rel:
            continue
        credential_ok = rel in CREDENTIAL_ENV_ALLOWED
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("//"):
                continue
            if not credential_ok and CREDENTIAL_ENV_PATTERN.search(line):
                errors.append(
                    f"daemon {rel}:{number}: names or maps the credential settings' environment; "
                    "use the CredentialConfig the composition root passes down"
                )
    return errors


def self_test() -> int:
    errors = check_tree(ROOT)
    if errors:
        print("self-test needs a clean tree:", *errors, sep="\n  ")
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        for rel in [
            "crates/yadorilink-daemon/src/lib.rs",
            "crates/yadorilink-daemon/src/shell_ipc.rs",
            "crates/yadorilink-daemon/src/shell_context.rs",
            "crates/yadorilink-daemon/Cargo.toml",
            "crates/yadorilink-local-capture/Cargo.toml",
            "crates/yadorilink-filesystem-sync/Cargo.toml",
            "crates/yadorilink-embedded-host/Cargo.toml",
            "crates/yadorilink-mobile-ffi/Cargo.toml",
            "Cargo.toml",
        ]:
            dest = tmp_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
        lib = tmp_root / "crates/yadorilink-daemon/src/lib.rs"
        lib.write_text(lib.read_text(encoding="utf-8").replace(f"{GATE}\npub mod control_socket;", "pub mod control_socket;"), encoding="utf-8")
        if not any("control_socket" in e for e in check_tree(tmp_root)):
            print("self-test: an ungated control_socket was not reported")
            return 1
        mobile = tmp_root / "crates/yadorilink-mobile-ffi/Cargo.toml"
        mobile.write_text(mobile.read_text(encoding="utf-8").replace("[dependencies]\n", '[dependencies]\nyadorilink-daemon = { path = "../yadorilink-daemon" }\n'), encoding="utf-8")
        if not any("mobile-ffi" in e and "yadorilink-daemon" in e for e in check_tree(tmp_root)):
            print("self-test: a direct daemon dependency of the mobile binding was not reported")
            return 1
        mobile.write_text((ROOT / "crates/yadorilink-mobile-ffi/Cargo.toml").read_text(encoding="utf-8").replace('["staticlib", "lib"]', '["staticlib", "cdylib", "lib"]'), encoding="utf-8")
        if not any("crate-type" in e for e in check_tree(tmp_root)):
            print("self-test: a cdylib mobile binding was not reported")
            return 1
        mobile.write_text((ROOT / "crates/yadorilink-mobile-ffi/Cargo.toml").read_text(encoding="utf-8"), encoding="utf-8")
        ctx = tmp_root / "crates/yadorilink-daemon/src/shell_context.rs"
        ctx.write_text(ctx.read_text(encoding="utf-8") + "\nfn leak() { let _ = crate::device_config::config_dir(); }\n", encoding="utf-8")
        if not any("shell_context.rs" in e for e in check_tree(tmp_root)):
            print("self-test: an environment read of the state directory was not reported")
            return 1
        leak = tmp_root / "crates/yadorilink-daemon/src/engine_leak.rs"
        leak.write_text('fn f() { let _ = std::env::var("YADORILINK_CREDENTIAL_FILE"); }\n', encoding="utf-8")
        found = check_env_reads(leak.parent)
        if not any("credential settings" in e for e in found):
            print("self-test: a credential variable in a new engine file was not reported")
            return 1
    print("self-test ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    if parser.parse_args().self_test:
        return self_test()
    errors = check_tree(ROOT)
    for e in errors:
        print(f"embedded-host surface: {e}")
    if errors:
        return 1
    print("embedded-host surface ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
