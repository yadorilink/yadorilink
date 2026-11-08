# Homebrew formula

`render-formula.py` renders the formula for one release from its release ledger
(`.github/channels/releases/<version>.json`), so Homebrew pins the same engine bundles, by
URL and sha256, that the signed channel manifest lists. Engine only (no Cask); macOS arm64 and
Linux x86_64.

```sh
python3 packaging/homebrew/render-formula.py .github/channels/releases/0.1.0-beta.9.json 0.1.0-beta.9 > yadorilink.rb
python3 packaging/homebrew/render-formula.py --self-test
```

The formula also installs `<prefix>/share/yadorilink/install-source` (`homebrew`). The daemon reads
that marker beside its real program and reports `install_source=homebrew`: self-update is disabled and
`yadorilink self-update` / `yadorilink uninstall` refuse and name `brew upgrade yadorilink` /
`brew uninstall yadorilink`.

## Bump procedure (after the release is published and its ledger is merged)

1. Render the formula from the new ledger into the tap (`yadorilink/homebrew-yadorilink`,
   `Formula/yadorilink.rb`); tap updates stay manual.
2. In the tap: `brew audit --strict --formula yadorilink`, `brew install yadorilink`,
   `yadorilink --version`, `brew uninstall yadorilink`; on macOS 14/15 and Linuxbrew.
3. Push the tap commit.
