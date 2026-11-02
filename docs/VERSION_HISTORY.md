# Version history: what is kept, where, and for how long

YadoriLink remembers earlier versions of the files in a shared folder so that a
change you did not want, from another device or from sync, can be undone. This
page says what that memory covers and what it does not.

## The promise

**A version's history stays on the device that actually held it.** Each device
keeps its own history. A device cannot restore a version it never had, and a
device that only fetched a file on demand has no copy of what it did not fetch.
Another device may still hold that version; `yadorilink versions` shows which
older versions this device has the content for.

### When a sync replaces or deletes a file

When a change that arrives from another device overwrites or deletes a file
that you have, YadoriLink keeps the version it replaced before it touches the
file. The kept versions of one file are:

- the newest 10 older versions, and
- every older version that was replaced within the last 30 days.

A version is dropped only when it is both outside the newest 10 and older than
30 days. This covers an overwrite and a delete that arrive by sync.

```bash
yadorilink versions ~/some/folder/report.txt        # list the kept versions
yadorilink restore ~/some/folder/report.txt         # bring back the previous one
yadorilink restore ~/some/folder/report.txt --version <id>
```

`restore` writes the old content back as a new change.

### Your own edits are not guaranteed

A version that you replace yourself, by saving a file or deleting it in your
folder, is recorded in the file's history, but its content is not guaranteed to
be kept. `yadorilink versions` marks older versions as `content=kept` or
`content=not-kept`; restoring one that is `not-kept` has to fetch the content
from another device and fails if no device has it.

### Always kept: pinned and leased items

A file or folder you pin with `yadorilink pin` is kept on this device, and so are the
versions a sync replaces (the same 10 versions and 30 days), even when the disk
is nearly full. A pin set on a folder above the file counts. The same holds
while this device keeps a copy so that another device can free its space.

If a pinned file is changing at the moment you pin it, `pin` says that its
previous versions are not safely kept yet; run `pin` again once the file has
settled.

### Ignored paths lose their history

When a path matches `.yadorilinkignore`, YadoriLink stops tracking it, and the
path's version history on this device is removed at that moment. The file in
your folder is not touched.

## When the disk is nearly full

Keeping a replaced version can require copying the file's content into
YadoriLink's own storage. If the volume has less free space than YadoriLink
needs to keep free (the volume's headroom, about 1 percent of the volume, at
least 256 MiB and at most 2 GiB), the replaced version is **not kept** and the
sync goes on. Nothing else is removed. A pinned or leased version is never given
up this way: its replacement waits for disk space like any other write.

You can see this in three places:

- `yadorilink status` shows, under the folder, how many versions were not kept
  for space in the last 30 days.
- `yadorilink versions <path>` lists the stretches of time whose versions are
  not kept, with the reason ("the disk was nearly full" or "the retention
  period ended").
- `yadorilink doctor` has a "version history" row with the rule, each linked
  folder's free space against its headroom, and the count above. It warns while
  a volume is at or below its headroom or versions were recently not kept.

There is no byte limit on the history in this version. `yadorilink gc --dry-run`
prints how much stored data only older versions use, so you can see what the
history costs. `yadorilink gc` itself deletes only data nothing references and
does not drop saved versions. Freeing the content of a file with
`yadorilink evict` says `held_as_history` when nothing could be freed because
an older version of the same file uses the same data.

## What is not covered

- A version that no device ever held: a file created and replaced between two
  syncs of a device that was offline is never seen by that device.
- A device whose local state was deleted: the history lives in that state.
- Anything outside a shared folder.
