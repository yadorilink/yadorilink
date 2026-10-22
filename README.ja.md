# YadoriLink

**クラウドのように同期し、ファイルはクラウドに置かない。**

[English README](README.md)

YadoriLink は、アカウント、デバイス、共有、権限の管理を提供しつつ、
ファイルの実体は利用者自身のデバイスにだけ置きます。

ファイルは、認可されたデバイス間で直接同期されます。
YadoriLink はデバイス同士の接続を仲介しますが、ファイルは保存しません。

> 1.0 より前のバージョンで、開発中です。

## 機能

- デバイス間の直接・暗号化同期
- アカウント単位の共有、権限管理、アクセスの取り消し
- バージョン履歴と競合コピーの保持
- オンデマンドのローカル容量管理（デスクトップアプリで利用できます。エンジン単体のリリースには含まれません）

対応プラットフォームは、macOS 14 以降（Apple シリコン）、Windows 11 25H2 以降（x64）、Linux x86_64（試験的対応）です。

### 提供状況

| 項目 | 状況 |
|---|---|
| エンジン（`yadorilink` コマンドラインとデーモン）macOS・Windows・Linux 向け | このリポジトリのリリースで提供中 |
| Linux 用 `.deb` パッケージ | 提供中 |
| macOS デスクトップアプリ（署名・公証済みの DMG、アプリ内アップデート） | 開発中（未公開） |
| Windows デスクトップアプリ（Microsoft Store 配布。初版はローカルに完全なコピーを持つ方式のみで、オンデマンドファイルには対応しません） | 開発中（未公開） |
| コマンドライン用の 1 行インストーラー、apt リポジトリ、Homebrew、WinGet | 計画中 |

## 入手方法

このリポジトリに含まれるのは、**エンジン**（同期デーモンと `yadorilink` コマンドライン）、
Linux パッケージ、Docker イメージ、Windows のエクスプローラー連携です。macOS と
Windows のデスクトップアプリは、このリポジトリとは別に配布する予定で、まだ公開していません。
公開時は [yadori.link](https://yadori.link/) でお知らせします。アプリを使う場合、エンジンの設定はアプリが行います。

エンジン単体（コマンドラインとデーモン。デスクトップアプリは含みません）は、
すべてのプラットフォーム向けに
[GitHub Releases](https://github.com/yadorilink/yadorilink/releases) で配布しています。

| プラットフォーム | ダウンロード |
|---|---|
| Linux (Debian/Ubuntu) | `yadorilink-linux-amd64.deb` |
| macOS、Windows、Linux | `yadorilink-engine-*.zip`（プラットフォームごとのエンジン。`yadorilink` コマンドラインとデーモンを含みます） |

各ファイルには、`.sha256` のチェックサムが付属します。エンジンバンドルの構成は
[`.github/release/engine-bundle-layout.md`](.github/release/engine-bundle-layout.md)
を参照してください。Linux のインストール手順、初回起動、更新、アンインストールは
[Linux の README](packaging/linux/README.md) に記載しています。

コマンドライン用インストーラーの仕組み、`yadorilink self-update` と
`yadorilink uninstall` の動作、アンインストール後に残るものについては、
[インストール・更新・アンインストールの FAQ](docs/INSTALL_FAQ.md)（英語）を参照してください。

**Windows で長期間オフラインだったデバイスについて:** 長期間オフラインだったために
同期が追いつけず、同期履歴の再構築が必要になった Windows デバイスは、現時点では
サポートしていません。この場合、YadoriLink は再構築を開始せず（ログに
"rebootstrap is blocked" と記録されます）、フォルダには変更を加えません。
同期が保たれているデバイスには影響しません。

リリース版は、既定で YadoriLink のコーディネーションサービス
（`https://control.yadori.link`）に接続します。別のコーディネーションサービスを使う場合は、
`yadorilink` コマンドまたはデーモンを実行する前に、環境変数
`YADORILINK_COORDINATION_ADDR` を設定してください
（例: `YADORILINK_COORDINATION_ADDR=http://127.0.0.1:8787`）。

## 使い始める

デスクトップアプリが公開されるまでは、どのプラットフォームでも、後述のコマンドラインを使ってください。
デスクトップアプリ（macOS、Windows）の公開後は、アプリをインストールして起動し、
ブラウザーで Google アカウントにサインインして、同期するフォルダーを選択します。
詳しい手順は、アプリに付属の案内を参照してください。

Linux にはデスクトップアプリはありません。コマンドラインの使い方は、どのプラットフォームでも共通です。

## エンジン単体の利用（コマンドライン）

お使いのプラットフォームに合わせて、`.deb`（Linux）でインストールするか、エンジンバンドルを展開し、
`yadorilink` と `yadorilink-daemon` に `PATH` を通します。
デスクトップアプリを使う場合はアプリがデーモンを起動しますが、エンジン単体の場合は
自分で起動します。`.deb` でインストールした Linux では
`systemctl --user enable --now yadorilink-daemon` を、それ以外では
`yadorilink daemon start` を実行します。続けて、次のコマンドを実行します。

```bash
yadorilink login
yadorilink device register --name "my-device"
yadorilink share create my-share --path ~/some/folder
yadorilink status
```

`yadorilink status` と `yadorilink doctor` で、デーモンの状態を確認できます。
共有フォルダーの履歴が再構築された場合、引き継げなかった版や手元の変更は削除されず、
「退避（preserved）」として保持されます。`yadorilink preserved list` で一覧を表示できます。
`preserved restore <item-id>` は退避された版を新しい変更として書き戻し、
`preserved retry <item-id>` は自分の変更を再投入し、
`preserved discard <item-id>` はその項目を削除します。

自分の別のデバイスを追加するには、次のコマンドを実行します。

```bash
yadorilink share joinable
yadorilink share join my-share --path ~/some/folder
```

他のユーザーと共有するには、次のコマンドを実行します。

```bash
yadorilink share invite my-share --role editor
# 招待を受けたユーザーは、次のコマンドを実行します。
yadorilink share accept <code> --path ~/some/folder
```

デーモンは、小さな Web ダッシュボードも提供します。待ち受けるのは `127.0.0.1` のみで、
ポートは 8484 です（`YADORILINK_HTTP_API_PORT` で変更できます）。
`yadorilink web status` を実行すると、ダッシュボードのアドレス、アクセストークンの保存場所、
別のコンピューターから SSH 経由で開く方法が表示されます。
`ssh -N -L 8484:127.0.0.1:8484 <user>@<host>` を実行し、手元のコンピューターで
`http://127.0.0.1:8484/` を開きます。ローカル側のポート番号は、ダッシュボードのポート番号と
同じにしてください（異なると 403 エラーになります）。

アクセストークンは、デーモンの起動ごとに新しく発行されます。Linux と macOS では、
デーモンを実行しているアカウントだけが読み取れるファイルに保存されます。ページに貼り付けて使い、
URL には含めないでください。ポートには同じマシン上のどのアカウントからも接続できるため、
他のローカルユーザーによるアクセスを防いでいるのは、トークンファイルのアクセス権限です。

## 更新とリセット（1.0 より前）

すべてのデバイスを、同じリリースに更新してください。1.0 より前のリリース間では、
互換性を保つための移行処理は提供されません。バージョンの非互換が原因で起動できない場合は、
YadoriLink のローカルのアプリケーション状態と認証情報を削除し、セットアップをやり直してください。
同期フォルダーとその中のファイルは削除されません。状態の保存場所は、Linux では
Linux の README に、macOS と Windows ではデスクトップアプリの案内に記載されています。

## 仕組み

YadoriLink は、「管理」と「保存」を分離しています。

コーディネーションサービスが扱うのは、アカウント、デバイスの識別、共有、権限、
接続の仲介です。ファイルの内容は利用者のデバイスにとどまり、認可されたデバイスの間でのみ転送されます。

## ソースからのビルド

開発用、または自分でビルドする場合の手順です。

エンジン（コマンドラインとデーモン）は、どのプラットフォームでも同じ手順でビルドできます。

```bash
cargo build --release -p yadorilink-cli -p yadorilink-daemon
./target/release/yadorilink --help
```

エンジンバンドルに含まれるのは、このビルド結果です。ワークスペース全体をビルドする場合は、
継続的インテグレーション（CI）と同じ次の手順を使います。

- `cargo build --workspace`（全プラットフォーム共通）
- Windows のエクスプローラー連携: `cargo build --release --manifest-path crates/yadorilink-shell-ext-windows/Cargo.toml`
  （独立したワークスペースで、Windows 専用です）

ビルド時の設定がない場合、ソースからビルドしたバイナリは、`YADORILINK_COORDINATION_ADDR`
を設定しない限り `http://127.0.0.1:8787` に接続します。リリース版は、
ビルド時に `YADORILINK_DEFAULT_COORDINATION_ADDR` を本番のコーディネーションサービスに設定しています。
ビルド時に同じ環境変数を設定すれば、独自の既定値を埋め込めます。実行時に参照される優先順位は、
`YADORILINK_COORDINATION_ADDR`、ビルド時の既定値、`http://127.0.0.1:8787` の順です。
デーモンは、`yadorilink daemon start` で自分で起動します。

## 開発

YadoriLink は、主に Rust で書かれています。

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

主なコンポーネントは次のとおりです。

- `crates/yadorilink-daemon`: 同期デーモン
- `crates/yadorilink-cli`: コマンドラインインターフェース
- `crates/yadorilink-transport`: デバイス間の接続
- `crates/yadorilink-shell-ext-windows`: エクスプローラー連携（Cloud Files ホストとシェル拡張）

プラットフォームごとのパッケージとインストールについては、
[`packaging/`](packaging/) 以下の README を参照してください。

## セキュリティ

[SECURITY.md](.github/SECURITY.md) を参照してください。

## コントリビュート

[CONTRIBUTING.md](.github/CONTRIBUTING.md) を参照してください。

## ライセンス

[GNU Affero General Public License v3.0 only](LICENSE)（AGPL-3.0-only）の下で提供されます。
公式アプリ、サードパーティの部品、コントリビュートとの関係は、
[LICENSING.md](LICENSING.md)（英語）を参照してください。

ホスト型のコーディネーションサービス（`control.yadori.link`）には、
[プライバシーポリシー](https://yadori.link/ja/privacy/)と
[利用規約](https://yadori.link/ja/terms/)が適用されます。
