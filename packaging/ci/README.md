# Install YadoriLink in CI

```yaml
steps:
  - uses: yadorilink/yadorilink/packaging/ci@v0.1.0-beta.9
    with:
      version: 0.1.0-beta.9
  - run: yadorilink --version
```

The action works on Linux x86_64 and macOS (Apple silicon) runners and fails on Windows runners (Windows ships through the Microsoft Store only). It downloads
the installer of exactly that release, verifies its build-provenance attestation with
`gh attestation verify`, and runs it with `--yes --no-modify-path --prefix`. The installer then
checks the signed release manifest and every file hash itself, so a CI install is verified like an
interactive one, and any failure fails the job. `bin-dir` is the output and is already on `PATH`.

Nothing is cached: restoring an installed directory would skip those checks, and the engine bundle
is a short signed download. Pin `version` to an exact release; the action has no "latest".

Without the action, or on a self-hosted runner without GitHub access, use the installer directly,
and for an offline or mirrored install use `--from FILE` with a signed manifest you downloaded
earlier (see the install FAQ).

`sh packaging/ci/test-install-yadorilink.sh` tests the script with stand-ins for `curl`, `gh` and
the installer.
