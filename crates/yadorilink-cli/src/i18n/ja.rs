//! Japanese text, keyed by the English wording in the source.

/// `english`'s Japanese text, if it has one.
pub(super) fn lookup(english: &str) -> Option<&'static str> {
    TABLE.iter().find(|(key, _)| *key == english).map(|(_, text)| *text)
}

/// Every entry, for the tests and for the copy review file.
#[cfg(test)]
pub(super) fn table() -> &'static [(&'static str, &'static str)] {
    TABLE
}

const TABLE: &[(&str, &str)] = &[
    // status: why a folder needs attention
    ("Next:", "対処:"),
    ("Needs attention", "確認が必要です"),
    (
        "This folder is paused by a problem and will retry.",
        "このフォルダーは問題のため停止しています。自動で再試行します。",
    ),
    (
        "This folder is waiting for free space on its disk; syncing resumes by itself once there is room.",
        "このフォルダーはディスクの空き容量を待っています。空きができれば同期は自動で再開します。",
    ),
    (
        "The system's limit on watched files is reached, so changes in this folder are picked up late or not at all until the limit is raised.",
        "システムが監視できるファイル数の上限に達したため、上限を引き上げるまでこのフォルダーの変更の検出が遅れるか、検出されません。",
    ),
    (
        "This folder is linked in more than one place, so nothing syncs.",
        "このフォルダーは複数の場所にリンクされているため、同期されません。",
    ),
    (
        "This folder is no longer linked to its shared folder (its ownership marker is gone, or it is not joined), so it does not sync. Its files are kept as they are.",
        "このフォルダーは共有フォルダーとのリンクが外れている(所有の印が失われたか、参加していない)ため、同期されません。ファイルはそのまま残ります。",
    ),
    (
        "This folder is no longer on the disk it was set up on, so deletions are not synced until that disk is back or the folder is linked again.",
        "このフォルダーは設定したディスク上にないため、そのディスクが戻るかフォルダーをリンクし直すまで、削除は同期されません。",
    ),
    (
        "This folder's disk has no identity that survives a remount (FAT, exFAT, xfs before Linux 6.5), so after it was mounted again it cannot be told from another disk holding a copy. Nothing syncs until you confirm it is the right disk.",
        "このフォルダーのディスクには再マウントしても変わらない識別情報がない(FAT、exFAT、Linux 6.5 より前の xfs)ため、再マウント後はコピーを持つ別のディスクと区別できません。正しいディスクであることを確認するまで同期されません。",
    ),
    (
        "This folder has no safe second copy; losing this disk would lose data.",
        "このフォルダーには安全な2つ目のコピーがありません。このディスクを失うとデータも失われます。",
    ),
    (
        "Immediate fetch from another device is not confirmed. Data already stored on this device may still be readable.",
        "他のデバイスからすぐに取得できることは確認できていません。このデバイスに保存済みのデータは読める場合があります。",
    ),
    (
        "It is not known yet whether missing files can be fetched.",
        "足りないファイルを取得できるかどうか、まだ分かっていません。",
    ),
    ("Some files have conflicting copies.", "競合するコピーがあるファイルがあります。"),
    (
        "A device is waiting for your approval to join this shared folder.",
        "あるデバイスがこの共有フォルダーへの参加の承認を待っています。",
    ),
    ("Some files were not applied to this device.", "このデバイスに反映されなかったファイルがあります。"),
    (
        "Its name cannot be used on this device: it collides with another file's name or is not allowed here.",
        "名前がこのデバイスで使えません。別のファイル名と衝突しているか、ここでは使えない名前です。",
    ),
    (
        "The existing file on this device cannot be read by you, so its update was not applied.",
        "このデバイス上の既存のファイルを読み取れないため、更新は反映されませんでした。",
    ),
    (
        "This device's history of this folder can no longer catch up from the other devices, so it takes a fresh copy of their state from a connected device. Your files here are kept.",
        "このデバイスのこのフォルダーの履歴は他のデバイスから追いつけなくなったため、接続中のデバイスから最新の状態を取り直します。ここにあるファイルは残ります。",
    ),
    (
        "A stored record of a file in this folder cannot be read back, so this folder cannot say whether its data is safe or fetchable until the record is repaired.",
        "このフォルダー内のファイルの保存済み記録が読み出せないため、記録が修復されるまで、データが安全か取得可能かを判断できません。",
    ),
    (
        "Some files in this folder cannot be read, so they are skipped and not synced. Nothing was deleted, and the rest of the folder keeps syncing.",
        "このフォルダー内の読み取れないファイルはスキップされ、同期されません。何も削除されておらず、残りのファイルは引き続き同期されます。",
    ),
    (
        "A folder could not be removed safely and was left under a temporary name; nothing was deleted.",
        "安全に削除できなかったフォルダーが一時的な名前のまま残されています。何も削除されていません。",
    ),
    ("This File Provider folder is not ready to use.", "この File Provider フォルダーはまだ使える状態ではありません。"),
    (
        "Some files in this File Provider folder keep failing to download.",
        "この File Provider フォルダーの一部のファイルがダウンロードに失敗し続けています。",
    ),
    (
        "Edits were kept beside a file instead of replacing it.",
        "編集内容は、ファイルを置き換えずにその横に保存されました。",
    ),
    (
        "A File Provider folder exists that no linked folder uses.",
        "どのリンク済みフォルダーからも使われていない File Provider フォルダーがあります。",
    ),
    ("The disk is almost full, so syncing is paused.", "ディスクがほぼいっぱいのため、同期を一時停止しています。"),
    ("The disk is running low on space.", "ディスクの空き容量が少なくなっています。"),
    ("Another device cannot be reached.", "他のデバイスに接続できません。"),
    ("Something went wrong recently while syncing.", "最近、同期中に問題が起きました。"),
    ("The last update did not finish.", "前回のアップデートは完了しませんでした。"),
    (
        "Update required: that device runs an older version, so syncing with it is paused until it is updated. It is online, and nothing is deleted.",
        "アップデートが必要です。そのデバイスが古いバージョンで動いているため、更新するまで同期を停止しています。相手はオンラインで、何も削除されません。",
    ),
    (
        "Update this device: that device runs a newer version, so syncing with it is paused until this one is updated. It is online, and nothing is deleted.",
        "このデバイスのアップデートが必要です。そのデバイスの方が新しいバージョンで動いているため、このデバイスを更新するまで同期を停止しています。相手はオンラインで、何も削除されません。",
    ),
    (
        "This device's database was restored from a backup or copied, so it will not sync under its old identity. Start over as a new device; your files stay and the old state is never reused.",
        "このデバイスのデータベースがバックアップから復元またはコピーされたため、以前の ID では同期されません。新しいデバイスとしてやり直してください。ファイルは残り、古い状態が再利用されることはありません。",
    ),
    (
        "This device cannot open the identity it signs changes with, so nothing it edits syncs. The daemon log names the cause; the usual one is that the cache directory holding the install record is not writable.",
        "このデバイスは変更の署名に使う ID を開けないため、編集した内容は同期されません。原因はデーモンのログに記録されます。多くの場合、インストール記録を置くキャッシュディレクトリに書き込めないことが原因です。",
    ),
    (
        "The record of the Windows sync folders was damaged and an older copy was used; a folder added most recently may be missing until it is rewritten.",
        "Windows の同期フォルダーの記録が壊れていたため、古いコピーを使用しました。最後に追加したフォルダーは、書き直されるまで表示されない場合があります。",
    ),
    (
        "This device replaced another one that may have held the only complete copy of some folders, and the service has not confirmed the replacement yet. It is retried automatically; your files are kept.",
        "このデバイスは、一部のフォルダーの唯一の完全なコピーを持っていた可能性のあるデバイスを置き換えましたが、サービスがまだ置き換えを確認していません。自動で再試行します。ファイルは残ります。",
    ),
    (
        "This device replaced another one that may have held the only complete copy of some folders. Acknowledge that changes made after the backup may be missing; the confirmation of the replacement waits for it. Your files are kept.",
        "このデバイスは、一部のフォルダーの唯一の完全なコピーを持っていた可能性のあるデバイスを置き換えました。バックアップ後の変更が失われている可能性があることを了承してください。置き換えの確認は、その了承を待っています。ファイルは残ります。",
    ),
    (
        "The device replacement cannot be confirmed yet; the reason is in brackets. It is retried every minute and goes through by itself once the reason clears and you have acknowledged that changes made after the backup may be missing (yadorilink device acknowledge-replacement).",
        "デバイスの置き換えはまだ確認できません。理由は角括弧内に表示されます。1分ごとに再試行し、理由が解消され、バックアップ後の変更が失われている可能性があることを了承(yadorilink device acknowledge-replacement)すると、自動的に完了します。",
    ),
    (
        "The confirmation of the device replacement was refused because you are signed out. Sign in again so it can go through; your files are kept.",
        "サインアウトしているため、デバイスの置き換えの確認が拒否されました。もう一度サインインすると完了します。ファイルは残ります。",
    ),
    (
        "The service is refusing requests until you accept the updated Terms. Your files, folders and this device are kept and nothing is unlinked; sync of what is already set up keeps its local state. Sign in again to review and accept the Terms in your browser.",
        "更新された利用規約に同意するまで、サービスはリクエストを拒否します。ファイル、フォルダー、このデバイスは残り、リンクも解除されません。設定済みの同期はローカルの状態を保ちます。もう一度サインインし、ブラウザーで利用規約を確認して同意してください。",
    ),
    (
        "Signing in again is required (the Terms may have changed): the service refused to renew this computer's session. Your files, folders and this device are kept. Sign in again to continue.",
        "もう一度サインインする必要があります(利用規約が変更された可能性があります)。サービスがこのコンピューターのセッションの更新を拒否しました。ファイル、フォルダー、このデバイスは残ります。続けるにはもう一度サインインしてください。",
    ),
    (
        "Deleting this account was requested on another device. Open the account's settings to cancel it if this was not you.",
        "別のデバイスからこのアカウントの削除が要求されました。心当たりがない場合は、アカウントの設定を開いて取り消してください。",
    ),
    (
        "This account is scheduled for deletion. Your files on this computer are kept; the account can still be restored from its settings before the grace period ends.",
        "このアカウントは削除が予定されています。このコンピューター上のファイルは残ります。猶予期間が終わる前なら、アカウントの設定から復元できます。",
    ),
    (
        "This account is about to be deleted: removing it would leave a shared folder without a safe copy, and the deletion goes ahead soon regardless. Review the account's settings now to restore it, or make another device a full copy.",
        "このアカウントはまもなく削除されます。削除すると、安全なコピーのない共有フォルダーが生じますが、削除は間もなく実行されます。今すぐアカウントの設定で復元するか、別のデバイスを完全なコピーにしてください。",
    ),
    ("Needs attention.", "確認が必要です。"),
    // status: what to do next
    (
        "link the folder again: yadorilink links shows it; if it is not joined, accept a new invite into it (yadorilink share accept <invite> --path <folder>), or unlink it (yadorilink unlink)",
        "フォルダーをリンクし直してください。yadorilink links で確認できます。参加していない場合は、新しい招待をそのフォルダーに受け入れる(yadorilink share accept <invite> --path <folder>)か、リンクを解除(yadorilink unlink)してください",
    ),
    (
        "check the right disk is mounted, then: yadorilink readopt <folder>",
        "正しいディスクがマウントされていることを確認してから、yadorilink readopt <folder> を実行してください",
    ),
    (
        "rename the file (on the device that has it, if the name is not allowed here)",
        "ファイル名を変更してください(この名前が使えない場合は、そのファイルがあるデバイスで)",
    ),
    (
        "make the file readable (grant yourself Read in the file's Security properties, or close the program that has it open)",
        "ファイルを読み取れるようにしてください(ファイルのセキュリティのプロパティで自分に読み取りを許可するか、ファイルを開いているプログラムを閉じてください)",
    ),
    (
        "make the file readable (chmod u+r)",
        "ファイルを読み取れるようにしてください(chmod u+r)",
    ),
    (
        "make the listed files readable (grant yourself Read in each file's Security properties, or close the program that has it open) or move them out of the folder; they are picked up again by the next scan, no restart needed (yadorilink status --details lists them)",
        "一覧のファイルを読み取れるようにする(各ファイルのセキュリティのプロパティで自分に読み取りを許可するか、開いているプログラムを閉じる)か、フォルダーの外へ移動してください。次回のスキャンで再び検出されるため、再起動は不要です(yadorilink status --details で一覧を確認できます)",
    ),
    (
        "make the listed files readable (for example chmod u+r <file>) or move them out of the folder; they are picked up again by the next scan, no restart needed (yadorilink status --details lists them)",
        "一覧のファイルを読み取れるようにする(例: chmod u+r <file>)か、フォルダーの外へ移動してください。次回のスキャンで再び検出されるため、再起動は不要です(yadorilink status --details で一覧を確認できます)",
    ),
    // commands: link, device, account
    (
        "Account deletion cancelled. Your account is {state}.",
        "アカウントの削除を取り消しました。アカウントの状態: {state}。",
    ),
    (
        "Account deletion requested. Nothing is deleted yet. To confirm, run:",
        "アカウントの削除を受け付けました。まだ何も削除されていません。確定するには、次を実行してください:",
    ),
    (
        "Acknowledged. The replacement is confirmed once every folder is complete on this computer.",
        "了承しました。このコンピューターのすべてのフォルダーが完全になった時点で、置き換えが確定されます。",
    ),
    (
        "Confirmed the disk at {local_path} as this folder's disk; it syncs again.",
        "{local_path} のディスクをこのフォルダーのディスクとして確認しました。同期を再開します。",
    ),
    (
        "Deleting your account needs a fresh sign-in.",
        "アカウントを削除するには、あらためてサインインが必要です。",
    ),
    (
        "Joined again: {path}",
        "再参加しました: {path}",
    ),
    (
        "Linked {local_path} to {group_name}",
        "{local_path} を {group_name} にリンクしました",
    ),
    (
        "Linked {local_path} to {group_name} (on-demand)",
        "{local_path} を {group_name} にリンクしました(オンデマンド)",
    ),
    (
        "No replacement is waiting for confirmation.",
        "確認待ちの置き換えはありません。",
    ),
    (
        "Not joined: {path} ({message})",
        "参加できませんでした: {path}({message})",
    ),
    (
        "Proceed with this risky link anyway? [y/N]",
        "リスクがありますが、このリンクを続行しますか? [y/N]",
    ),
    (
        "Registered device: {device_id}",
        "デバイスを登録しました: {device_id}",
    ),
    (
        "Registered new device {new_id} (replacing {old_id}).",
        "新しいデバイス {new_id} を登録しました({old_id} を置き換え)。",
    ),
    (
        "Remove device {device_id} and revoke its access to every folder group? Files already on that device stay on its disk.",
        "デバイス {device_id} を削除し、すべてのフォルダーグループへのアクセスを取り消しますか? そのデバイスに既にあるファイルはディスクに残ります。",
    ),
    (
        "Removed device: {device_id}",
        "デバイスを削除しました: {device_id}",
    ),
    (
        "Start over as a new device? This computer is signed out and gets a new device identity; its old device stays on your account, signed out. Files on this computer and its synced history are kept, and the folders you linked are joined again.",
        "新しいデバイスとしてやり直しますか? このコンピューターはサインアウトされ、新しいデバイス ID が割り当てられます。古いデバイスはサインアウトした状態でアカウントに残ります。このコンピューター上のファイルと同期履歴は残り、リンクしていたフォルダーには再参加します。",
    ),
    (
        "The management session ended.",
        "管理セッションが終了しました。",
    ),
    (
        "The old device identity {retired_device_id} is retired and this computer is signed out. Run `yadorilink login`, then `yadorilink device start-over` again to register it as a new device.",
        "古いデバイス ID {retired_device_id} は廃止され、このコンピューターはサインアウトされました。`yadorilink login` を実行してから、もう一度 `yadorilink device start-over` を実行し、新しいデバイスとして登録してください。",
    ),
    (
        "The old device {old_id} is still listed on your account as signed out. Remove it with `yadorilink device remove {old_id} --force` once the new device has your folders.",
        "古いデバイス {old_id} は、サインアウトした状態でまだアカウントに表示されています。新しいデバイスにフォルダーがそろったら、`yadorilink device remove {old_id} --force` で削除してください。",
    ),
    (
        "This computer was restored from a backup and cannot check whether changes made after that backup are missing. Confirm the replacement anyway? Anything changed after the backup may be gone for good if no other device holds it.",
        "このコンピューターはバックアップから復元されたため、バックアップ後の変更が失われていないかを確認できません。それでも置き換えを確定しますか? バックアップ後に変更された内容は、他のデバイスが持っていなければ完全に失われている可能性があります。",
    ),
    (
        "This confirmation token is shown only once. After you confirm, a grace period starts during which you can still cancel with `yadorilink account delete cancel`.",
        "この確認トークンは一度しか表示されません。確定すると猶予期間が始まり、その間は `yadorilink account delete cancel` で取り消せます。",
    ),
    (
        "This export contains only your coordination-plane records -- never your file contents, file or folder names, or paths, which the server never holds.",
        "このエクスポートには、コーディネーション側の記録だけが含まれます。サーバーが保持しない、ファイルの内容、ファイル名やフォルダー名、パスは含まれません。",
    ),
    (
        "This link has {count} risk(s) listed above.",
        "このリンクには、上に挙げた {count} 件のリスクがあります。",
    ),
    (
        "Unlinked {local_path}",
        "{local_path} のリンクを解除しました",
    ),
    (
        "Wrote your account data export to {path}.",
        "アカウントデータのエクスポートを {path} に書き出しました。",
    ),
    (
        "You can still cancel with `yadorilink account delete cancel` until the grace period ends; only finalization is irreversible.",
        "猶予期間が終わるまでは `yadorilink account delete cancel` で取り消せます。元に戻せないのは最終的な削除だけです。",
    ),
    (
        "dry run: no link registered ({verdict})",
        "ドライラン: リンクは登録されていません({verdict})",
    ),
    (
        "looks safe to link",
        "リンクして問題なさそうです",
    ),
    (
        "risky conditions found",
        "リスクのある条件が見つかりました",
    ),
    (
        "warning: --force set -- if this device is the sole complete copy for this folder's group with no other confirmed-ready complete copy, unlinking anyway may permanently lose the only copy of that data",
        "警告: --force が指定されています。このデバイスがこのフォルダーグループ唯一の完全なコピーで、他に確認済みの完全なコピーがない場合、このままリンクを解除すると、そのデータの唯一のコピーが完全に失われる可能性があります",
    ),
    // commands: daemon, preserved, send, report, share, backup, version history
    (
        "(daemon not running — showing local consent state only)",
        "(デーモンが動作していません。ローカルの同意状態のみを表示しています)",
    ),
    (
        "Backup readiness (non-sensitive config and link metadata only):",
        "バックアップの準備状況(機密を含まない設定とリンクのメタデータのみ):",
    ),
    (
        "Cancelled invite: {invite_id}",
        "招待を取り消しました: {invite_id}",
    ),
    (
        "Created folder group {group_id} and linked it at {path}",
        "フォルダーグループ {group_id} を作成し、{path} にリンクしました",
    ),
    (
        "Daemon stopping.",
        "デーモンを停止しています。",
    ),
    (
        "Deleted folder group: {group_name}",
        "フォルダーグループを削除しました: {group_name}",
    ),
    (
        "Deleted queue item {report_id}",
        "キューの項目を削除しました: {report_id}",
    ),
    (
        "Discarded {item_id}.",
        "{item_id} を破棄しました。",
    ),
    (
        "Inbox is empty.",
        "受信トレイは空です。",
    ),
    (
        "No conflicted files.",
        "競合しているファイルはありません。",
    ),
    (
        "No linked-folder metadata was saved in this backup.",
        "このバックアップには、リンクしたフォルダーのメタデータは保存されていません。",
    ),
    (
        "No originals are kept.",
        "保持されている元ファイルはありません。",
    ),
    (
        "No queue item found with id {report_id}",
        "ID {report_id} のキュー項目は見つかりませんでした",
    ),
    (
        "No retained versions for {local_path}.",
        "{local_path} に保持されているバージョンはありません。",
    ),
    (
        "Not submitted.",
        "送信しませんでした。",
    ),
    (
        "Nothing has been sent from this device.",
        "このデバイスからはまだ何も送信していません。",
    ),
    (
        "Nothing is preserved.",
        "保存されているものはありません。",
    ),
    (
        "Nothing to pause: no folders are linked.",
        "一時停止するものがありません。リンクされたフォルダーがありません。",
    ),
    (
        "Nothing to resume: no folders are linked.",
        "再開するものがありません。リンクされたフォルダーがありません。",
    ),
    (
        "Queue is empty.",
        "キューは空です。",
    ),
    (
        "Recovery coverage:",
        "復旧できる範囲:",
    ),
    (
        "Redacted before this preview (categories, occurrence counts):",
        "このプレビューの前に伏せ字にしたもの(種類と件数):",
    ),
    (
        "Restored non-sensitive config (coordination address).",
        "機密を含まない設定(コーディネーションのアドレス)を復元しました。",
    ),
    (
        "Restored {item_id}: it is written back as a new version; the item is kept.",
        "{item_id} を復元しました。新しいバージョンとして書き戻され、項目は残ります。",
    ),
    (
        "Restored {local_path} from trash",
        "{local_path} をごみ箱から復元しました",
    ),
    (
        "Revoked share edge: {edge_id}",
        "共有の接続を取り消しました: {edge_id}",
    ),
    (
        "Send link {link_id} canceled.",
        "送信リンク {link_id} を取り消しました。",
    ),
    (
        "Submission failed but the report was queued locally for automatic retry.",
        "送信に失敗しましたが、レポートはローカルのキューに入れ、自動で再試行します。",
    ),
    (
        "Sync resumed.",
        "同期を再開しました。",
    ),
    (
        "The daemon will no longer start at login.",
        "ログイン時にデーモンが自動で起動しなくなります。",
    ),
    (
        "Transfer {transfer_id} stopped. A finished transfer is left as it is; retry a stopped one to start it again.",
        "転送 {transfer_id} を停止しました。完了した転送はそのままです。停止した転送は再試行すると、もう一度開始できます。",
    ),
    (
        "Trash is empty.",
        "ごみ箱は空です。",
    ),
];
