// Loads the real page in jsdom with a stubbed fetch and checks the
// appliance summary. Run: npm install && npm test (in this directory).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

const html = readFileSync(new URL("../webui/index.html", import.meta.url), "utf8")
  .replaceAll("%%CSP_NONCE%%", "test");

const GIB = 1024 ** 3;
const link = (name, over) => Object.assign({
  local_path: "/srv/yadorilink/" + name, group_id: "g-" + name, paused: false,
  degraded: false, ambiguous: false, capture_volume_changed: false, capture_volume_unconfirmed: false,
  local_storage_state: "LOCAL_STORAGE_STATE_FULL_COPY", materialization_policy: "eager", hydrated_count: 3, placeholder_count: 0,
  conflict_count: 0, protection: "DATA_PROTECTION_PROTECTED", protection_device_ids: ["laptop"],
  availability: "PRODUCT_AVAILABILITY_AVAILABLE", availability_offline_device_ids: [],
}, over);

const open = [];
// The page reconnects its event stream forever; closing the windows ends it.
after(() => open.forEach((d) => d.window.close()));

async function render(status, routes = {}, pageUrl = "http://127.0.0.1:8484/") {
  const dom = new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true, url: pageUrl });
  open.push(dom);
  const json = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
  dom.window.__calls = [];
  dom.window.__headers = [];
  dom.window.fetch = (path, opts = {}) => {
    dom.window.__headers.push({ path, auth: (opts.headers || {}).Authorization });
    if (opts.method === "POST") dom.window.__calls.push({ path, body: JSON.parse(opts.body || "{}") });
    if (path in routes) return json(routes[path]);
    if (path === "/api/status") return json(status);
    if (path === "/api/conflicts") return json({ conflicts: [] });
    if (path === "/api/trash") return json({ files: [] });
    if (path === "/api/preserved") return json({ items: [] });
    if (path === "/api/devices") return json({ devices: [] });
    if (path === "/api/retained") return json({ items: [] });
    if (path === "/api/transfers") return json({ received: [], sent: [] });
    return Promise.resolve({ ok: false, status: 503, body: null, json: () => Promise.resolve({}) });
  };
  dom.window.TextDecoder = TextDecoder;
  // The script ran at load with the real fetch; boot again through the gate.
  dom.window.document.getElementById("token-input").value = "t";
  dom.window.document.getElementById("token-submit").click();
  for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 10));
  return dom.window.document;
}

const base = {
  overall_state: "healthy", attention_reasons: [], peers: [],
  volumes: [{ path: "<block store>", state: "ok", available_bytes: 800 * GIB, headroom_bytes: 0, total_bytes: 2000 * GIB }],
  block_store: { total_bytes: 400 * GIB }, update: {},
};
const text = (doc, id) => doc.getElementById(id).textContent;

test("summary names complete copies, the disk and what this device protects", async () => {
  const doc = await render({ ...base, links: [link("Photos"), link("Docs"), link("Cache", { materialization_policy: "on-demand" })] });
  const copy = text(doc, "appliance-copy");
  assert.match(copy, /Keeping a complete copy of 2 folders/);
  assert.match(copy, /Protecting for your other devices: Photos, Docs/);
  assert.doesNotMatch(copy, /Cache/);
  const disk = text(doc, "appliance-disk");
  assert.match(disk, /Disk capacity.*2\.0 TB/);
  assert.match(disk, /Free space.*800\.0 GB/);
  assert.match(disk, /Used by YadoriLink.*400\.0 GB/);
  assert.match(text(doc, "overall-state"), /Healthy/);
  assert.match(text(doc, "links-table"), /Complete copy/);
});

test("attention is plain words, never daemon codes", async () => {
  const doc = await render({
    ...base, overall_state: "degraded",
    attention_reasons: ["durability_at_risk:g-Photos", "low_disk:/srv", "peer_disconnected:abc", "mystery:x"],
    links: [link("Photos", { protection: "DATA_PROTECTION_AT_RISK" })],
  });
  const t = text(doc, "overall-state");
  assert.match(t, /Needs attention/);
  assert.match(t, /Photos has no other confirmed copy yet\./);
  assert.match(t, /Free space is running low\./);
  assert.match(t, /Something needs attention\./);
  assert.doesNotMatch(t, /durability_at_risk|low_disk|peer_disconnected|mystery/);
});

test("a version-mismatched device reads update required, not unreachable", async () => {
  const doc = await render({
    ...base, overall_state: "attention",
    attention_reasons: ["peer_newer:abc"],
    peers: [{ device_id: "abc", reachability: "PEER_REACHABILITY_CONNECTED", route_kind: "ROUTE_KIND_DIRECT", version_skew: "VERSION_SKEW_PEER_NEWER" }],
  });
  assert.match(text(doc, "overall-state"), /Update this device to sync with device abc/);
  assert.doesNotMatch(text(doc, "overall-state"), /peer_update_required|can't be reached/);
  assert.match(text(doc, "connections-table"), /newer version: update this device/);
  assert.doesNotMatch(text(doc, "connections-table"), /unreachable/);
});

test("an older device is named and told to update", async () => {
  const doc = await render({
    ...base, overall_state: "attention",
    attention_reasons: ["peer_update_required:abc"],
    peers: [{ device_id: "abc", reachability: "PEER_REACHABILITY_CONNECTED", route_kind: "ROUTE_KIND_DIRECT", version_skew: "VERSION_SKEW_PEER_OLDER" }],
  });
  assert.match(text(doc, "overall-state"), /Update device abc to sync/);
  assert.match(text(doc, "connections-table"), /older version: update device abc/);
});

test("a folder whose disk is not confirmed says so and does not count as protecting", async () => {
  const doc = await render({
    ...base, overall_state: "attention", attention_reasons: ["volume_unconfirmed:g-Photos"],
    links: [link("Photos", { capture_volume_unconfirmed: true })],
  });
  assert.match(text(doc, "overall-state"), /The disk for Photos changed or was remounted\. Confirm it's the right disk to resume\./);
  assert.doesNotMatch(text(doc, "overall-state"), /volume_unconfirmed/);
  assert.doesNotMatch(text(doc, "appliance-copy"), /Protecting for your other devices: Photos/);
  const table = text(doc, "links-table");
  assert.match(table, /disk not confirmed/);
  assert.match(table, /Confirm disk/);
});

test("paused and empty states", async () => {
  let doc = await render({ ...base, links: [link("Photos", { paused: true })] });
  assert.match(text(doc, "appliance-copy"), /nothing is being protected/);
  doc = await render({ ...base, links: [] });
  assert.match(text(doc, "appliance-copy"), /No folders yet/);
});

test("add-a-folder defaults to a complete copy", async () => {
  const doc = await render({ ...base, links: [] });
  const mode = doc.getElementById("add-mode");
  assert.equal(mode.value, "eager");
  assert.equal(mode.options[0].textContent, "Keep a complete copy on this device");
});

test("no internal words in user-facing text", async () => {
  const doc = await render({ ...base, links: [link("Photos")] });
  assert.doesNotMatch(doc.body.textContent, /custody|writer|lease|replica/i);
});

test("only folders holding every file count as protecting", async () => {
  const doc = await render({ ...base, links: [
    link("Photos"),
    link("Docs", { local_storage_state: "LOCAL_STORAGE_STATE_PARTIALLY_MATERIALIZED" }),
  ] });
  const copy = text(doc, "appliance-copy");
  assert.match(copy, /Keeping a complete copy of 1 folder/);
  assert.match(copy, /Protecting for your other devices: Photos(?!, Docs)/);
  assert.match(copy, /Copying\u2026 Docs/);
  assert.match(text(doc, "links-table"), /Complete copy \(copying\u2026\)/);
});

test("a folder off its disk, degraded or ambiguous is not protecting", async () => {
  for (const over of [{ capture_volume_changed: true }, { degraded: true }, { ambiguous: true }, { policy_stale: true }]) {
    const doc = await render({ ...base, links: [link("C:\\Data\\Photos", over)] });
    const copy = text(doc, "appliance-copy");
    assert.doesNotMatch(copy, /Protecting for your other devices/);
    assert.match(copy, /Not keeping a complete copy/);
    assert.doesNotMatch(copy, /Copying/);
  }
  const doc = await render({ ...base, overall_state: "attention", attention_reasons: ["volume_changed:g-Photos"], links: [link("Photos", { capture_volume_changed: true })] });
  assert.match(text(doc, "overall-state"), /The disk for Photos isn't available\. Reconnect it to keep the copy\./);
});

test("folder names split on both separators", async () => {
  const doc = await render({ ...base, links: [link("x", { local_path: "D:\\Share\\Photos" })] });
  assert.match(text(doc, "appliance-copy"), /Protecting for your other devices: Photos/);
});

test("a paused folder that is not complete is not shown as copying", async () => {
  const doc = await render({ ...base, links: [
    link("Photos", { paused: true, local_storage_state: "LOCAL_STORAGE_STATE_PARTIALLY_MATERIALIZED" }),
  ] });
  assert.doesNotMatch(text(doc, "appliance-copy"), /Copying/);
  assert.doesNotMatch(text(doc, "links-table"), /copying/);
  assert.match(text(doc, "links-table"), /Complete copy \(not complete yet\)/);
});

test("a folder on another disk shows that disk's own free space", async () => {
  const doc = await render({
    ...base,
    volumes: [
      ...base.volumes,
      { path: "/srv/yadorilink/Photos", state: "ok", available_bytes: 800 * GIB, headroom_bytes: 0, total_bytes: 2000 * GIB },
      { path: "/mnt/usb/Archive", state: "low", available_bytes: 5 * GIB, headroom_bytes: 0, total_bytes: 100 * GIB },
    ],
    links: [link("Photos"), link("Archive", { local_path: "/mnt/usb/Archive" })],
  });
  const disk = text(doc, "appliance-disk");
  assert.match(disk, /Archive.*5\.0 GB free of 100\.0 GB/);
  assert.match(disk, /Free space.*800\.0 GB/);
  assert.match(disk, /Photos: 800\.0 GB free of 2\.0 TB/);
});

test("folders on disks reporting the same numbers share one line, none omitted", async () => {
  const same = { state: "ok", available_bytes: 50 * GIB, headroom_bytes: 0, total_bytes: 100 * GIB };
  const doc = await render({
    ...base,
    volumes: [...base.volumes, { path: "/mnt/a/One", ...same }, { path: "/mnt/b/Two", ...same }],
    links: [link("One", { local_path: "/mnt/a/One" }), link("Two", { local_path: "/mnt/b/Two" })],
  });
  assert.match(text(doc, "appliance-disk"), /One, Two: 50\.0 GB free of 100\.0 GB/);
});

test("a folder waiting for its source device is not shown as copying", async () => {
  const doc = await render({ ...base, links: [
    link("Photos", {
      local_storage_state: "LOCAL_STORAGE_STATE_PARTIALLY_MATERIALIZED",
      availability: "PRODUCT_AVAILABILITY_WAITING_FOR_PEER", availability_offline_device_ids: ["laptop"],
    }),
  ] });
  const copy = text(doc, "appliance-copy");
  assert.doesNotMatch(copy, /Copying/);
  assert.match(copy, /Waiting for a device: Photos/);
  assert.doesNotMatch(text(doc, "links-table"), /copying/);
  assert.match(text(doc, "links-table"), /Complete copy \(waiting for a device\)/);
});

test("a folder whose content no reachable device is known to have is not shown as copying", async () => {
  const doc = await render({ ...base, links: [
    link("Photos", {
      local_storage_state: "LOCAL_STORAGE_STATE_PARTIALLY_MATERIALIZED",
      availability: "PRODUCT_AVAILABILITY_WAITING_FOR_EXACT_CONTENT",
    }),
  ] });
  const copy = text(doc, "appliance-copy");
  assert.doesNotMatch(copy, /Copying/);
  assert.doesNotMatch(copy, /Waiting for a device: Photos/);
  assert.match(copy, /Waiting for files to become available: Photos/);
  assert.match(text(doc, "links-table"), /Complete copy \(waiting for files\)/);
});

test("removing a device says which folders were handed to another device", async () => {
  const doc = await render(base, {
    "/api/devices": { devices: [
      { device_id: "this", device_name: "NAS", is_this_device: true, online: true },
      { device_id: "old", device_name: "Old laptop", is_this_device: false, online: false },
    ] },
    "/api/devices/remove": { ok: true, handoffs: [
      { group_id: "g-photos", target_device_id: "this", lease_id: "l1", membership_generation: 3 },
    ] },
  });
  doc.defaultView.confirm = () => true;
  doc.querySelector("button[data-remove-device]").click();
  for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 10));
  const note = text(doc, "devices-note");
  assert.match(note, /Removed Old laptop/);
  assert.match(note, /1 folder on another device: g-photos on NAS/);
});

const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 10)); };
const posts = (doc) => doc.defaultView.__calls;

test("a resolvable conflict offers Keep this and Keep both, and each posts its resolution", async () => {
  const doc = await render(base, {
    "/api/conflicts": { conflicts: [
      { path: "a (conflicted copy).txt", absolute_path: "/srv/a (conflicted copy).txt", local_path: "/srv", size: 5, resolvable: true },
      { path: "b (conflicted copy).txt", absolute_path: "/srv/b (conflicted copy).txt", local_path: "/srv", size: 5, resolvable: false },
    ] },
    "/api/conflicts/resolve": { kept_path: "/srv/a.txt" },
  });
  doc.defaultView.confirm = () => true;
  const buttons = doc.querySelectorAll("#conflicts-table button[data-resolve]");
  assert.equal(buttons.length, 2, "only the resolvable copy has actions");
  buttons[1].click();
  await settle();
  buttons[0].click();
  await settle();
  assert.deepEqual(posts(doc).map((c) => [c.path, c.body.resolution, c.body.path]), [
    ["/api/conflicts/resolve", "keep_both", "/srv/a (conflicted copy).txt"],
    ["/api/conflicts/resolve", "keep_this", "/srv/a (conflicted copy).txt"],
  ]);
});

test("Keep this asks first and posts nothing when declined", async () => {
  const doc = await render(base, {
    "/api/conflicts": { conflicts: [{ path: "a.txt", absolute_path: "/srv/a.txt", local_path: "/srv", size: 1, resolvable: true }] },
  });
  doc.defaultView.confirm = () => false;
  doc.querySelector('button[data-resolve="keep_this"]').click();
  await settle();
  assert.equal(posts(doc).length, 0);
});

test("deleted items restore one at a time, or the whole folder when one operation deleted them", async () => {
  const doc = await render(base, {
    "/api/trash": { files: [
      { path: "x.txt", absolute_path: "/srv/x.txt", local_path: "/srv", size: 10, deleted_at_unix_nanos: 1e18, deleted_by_operation: false },
      { path: "y.txt", absolute_path: "/srv/y.txt", local_path: "/srv", size: 10, deleted_at_unix_nanos: 1e18, deleted_by_operation: true },
    ] },
    "/api/trash/restore": { restored_paths: ["/srv/y.txt"] },
  });
  assert.equal(doc.querySelectorAll('#trash-table button[data-trash="whole"]').length, 1);
  doc.querySelector('#trash-table button[data-trash="whole"]').click();
  await settle();
  doc.querySelector('#trash-table button[data-trash="one"]').click();
  await settle();
  assert.deepEqual(posts(doc).map((c) => c.body), [
    { path: "/srv/y.txt", whole_operation: true },
    { path: "/srv/x.txt", whole_operation: false },
  ]);
});

test("the kept-aside card is hidden when empty and offers Retry, Restore or nothing by what is available", async () => {
  const empty = await render(base);
  assert.equal(empty.getElementById("preserved-card").hidden, true);

  const doc = await render(base, {
    "/api/preserved": { items: [
      { kind: "own_unit", group_id: "g", item_id: "i1", recovery_id: "r1", paths: ["a", "b"], content: "complete" },
      { kind: "file", group_id: "g", item_id: "i2", path: "p.txt", size: 3, content: "complete" },
      { kind: "file", group_id: "g", item_id: "i3", path: "q.txt", size: 3, content: "unavailable" },
    ] },
    "/api/preserved/action": { ok: true },
  });
  assert.equal(doc.getElementById("preserved-card").hidden, false);
  const table = doc.getElementById("preserved-table");
  assert.match(table.textContent, /Your changes held back \(2 item\(s\)\)/);
  assert.equal(table.querySelectorAll('button[data-preserved="retry"]').length, 1);
  assert.equal(table.querySelectorAll('button[data-preserved="restore"]').length, 1);
  assert.match(table.textContent, /content not available/);
  assert.equal(table.querySelectorAll('button[data-preserved="discard"]').length, 3);
  doc.defaultView.confirm = () => true;
  table.querySelector('button[data-preserved="restore"]').click();
  await settle();
  assert.deepEqual(posts(doc)[0], { path: "/api/preserved/action", body: { group_id: "g", item_id: "i2", action: "restore" } });
});

test("an invite shows its code once, or the daemon's refusal", async () => {
  const ok = await render({ ...base, links: [link("Photos")] }, {
    "/api/share/invite": { code: "ABC-123", expires_at_unix: 4102444800 },
  });
  ok.getElementById("invite-role").value = "viewer";
  ok.getElementById("invite-mint").click();
  await settle();
  assert.match(text(ok, "invite-result"), /ABC-123/);
  assert.deepEqual(posts(ok)[0].body, { group_id: "g-Photos", role: "viewer", requires_approval: false });

  const none = await render(base);
  none.getElementById("invite-mint").click();
  await settle();
  assert.match(text(none, "invite-result"), /Link a folder first\./);
  assert.equal(posts(none).length, 0);
});

test("deleting a folder group asks first, and sends the cross-account acknowledgement only after a second confirmation", async () => {
  const doc = await render({ ...base, links: [link("Photos")] });
  const win = doc.defaultView;
  const answers = [];
  win.confirm = (m) => { answers.push(m); return true; };
  // First request is refused for members on other accounts; the retry succeeds.
  let calls = 0;
  const realFetch = win.fetch;
  win.fetch = (path, opts) => {
    if (path === "/api/share/delete") {
      win.__calls.push({ path, body: JSON.parse(opts.body) });
      calls++;
      return calls === 1
        ? Promise.resolve({ ok: false, status: 400, json: () => Promise.resolve({ error: "refused: acknowledge cross-account members" }) })
        : Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) });
    }
    return realFetch(path, opts);
  };
  doc.querySelector('button[data-action="delete-group"]').click();
  await settle();
  assert.deepEqual(posts(doc).map((c) => c.body), [
    { group_id: "g-Photos", acknowledge_cross_account_members: false },
    { group_id: "g-Photos", acknowledge_cross_account_members: true },
  ]);
  assert.equal(answers.length, 2);
  assert.match(answers[1], /other accounts/);
});

test("declining the first confirmation deletes nothing", async () => {
  const doc = await render({ ...base, links: [link("Photos")] });
  doc.defaultView.confirm = () => false;
  doc.querySelector('button[data-action="delete-group"]').click();
  await settle();
  assert.equal(posts(doc).length, 0);
});

test("members of a folder group are listed with Revoke, or Deny while waiting for approval", async () => {
  const doc = await render({ ...base, links: [link("Photos")] }, {
    "/api/shares": { edges: [
      { edge_id: "e1", group_id: "g-Photos", device_id: "dev-active", state: "active" },
      { edge_id: "e2", group_id: "g-Photos", device_id: "dev-wait", state: "pending_approval" },
      { edge_id: "e3", group_id: "g-other-folder", device_id: "dev-x", state: "active" },
    ] },
    "/api/share/revoke": { ok: true, handoffs: [] },
  });
  const labels = [...doc.querySelectorAll("#shares-table button[data-revoke-group]")].map((b) => b.textContent);
  assert.deepEqual(labels, ["Revoke", "Deny"], "a group not linked on this device is not listed");
  doc.defaultView.confirm = () => true;
  doc.querySelector("#shares-table button[data-revoke-device=dev-wait]").click();
  await settle();
  assert.deepEqual(posts(doc).map((c) => c.body), [{ group_id: "g-Photos", device_id: "dev-wait" }]);
  assert.match(text(doc, "shares-note"), /Done\./);
});

test("declining the revoke confirmation sends nothing", async () => {
  const doc = await render({ ...base, links: [link("Photos")] }, {
    "/api/shares": { edges: [{ edge_id: "e1", group_id: "g-Photos", device_id: "d", state: "active" }] },
  });
  doc.defaultView.confirm = () => false;
  doc.querySelector("#shares-table button[data-revoke-group]").click();
  await settle();
  assert.equal(posts(doc).length, 0);
});

test("transfers: hidden when none; Retry and Cancel by direction and state", async () => {
  const none = await render(base);
  assert.equal(none.getElementById("transfers-card").hidden, true);

  const file = [{ path: "a.txt", size: 10 }];
  const doc = await render(base, {
    "/api/transfers": {
      received: [
        { transfer_id: "r-live", device_id: "laptop", files: file, total_size: 10, status: "in_progress", failure: "", bytes_done: 4 },
        { transfer_id: "r-failed", device_id: "laptop", files: file, total_size: 10, status: "failed", failure: "unreachable", bytes_done: 0 },
        { transfer_id: "r-done", device_id: "laptop", files: file, total_size: 10, status: "completed", failure: "", bytes_done: 10 },
      ],
      sent: [
        { transfer_id: "s-offered", device_id: "laptop", files: file, total_size: 10, status: "offered", failure: "", can_retry: false, bytes_done: 0 },
        { transfer_id: "s-canceled", device_id: "laptop", files: file, total_size: 10, status: "canceled", failure: "receiver_canceled", can_retry: true, bytes_done: 0 },
      ],
    },
    "/api/transfers/cancel": { ok: true },
    "/api/transfers/retry": { offered: true },
  });
  assert.equal(doc.getElementById("transfers-card").hidden, false);
  const q = (action, id) => doc.querySelector(`button[data-transfer-action=${action}][data-transfer=${id}]`);
  assert.ok(q("cancel", "r-live") && q("cancel", "s-offered"), "going transfers can be stopped");
  assert.ok(q("retry", "r-failed") && q("retry", "s-canceled"), "failed or canceled ones can be retried");
  assert.equal(q("retry", "r-done"), null);
  assert.equal(q("cancel", "r-done"), null);
  assert.equal(q("retry", "s-offered"), null, "a sent offer the daemon does not allow retrying has no Retry");
  assert.match(text(doc, "transfers-table"), /unreachable/);
  doc.defaultView.confirm = () => true;
  q("retry", "s-canceled").click();
  await settle();
  q("cancel", "r-live").click();
  await settle();
  assert.deepEqual(posts(doc).map((c) => [c.path, c.body]), [
    ["/api/transfers/retry", { transfer_id: "s-canceled", direction: "sent" }],
    ["/api/transfers/cancel", { transfer_id: "r-live", direction: "received" }],
  ]);
});

test("a page opened through a managing device sends its session secret and drops it from the address", async () => {
  const secret = "ab".repeat(32);
  const doc = await render({ ...base, links: [link("Photos")] }, {}, "http://127.0.0.1:50123/#" + secret);
  const api = doc.defaultView.__headers.filter((h) => h.path.startsWith("/api/"));
  assert.ok(api.length > 0);
  assert.ok(api.every((h) => h.auth === "Bearer " + secret), JSON.stringify(api));
  assert.equal(doc.defaultView.location.hash, "", "the secret is taken off the address bar");
  const stored = Object.keys(doc.defaultView.localStorage).map((k) => doc.defaultView.localStorage.getItem(k));
  assert.ok(!stored.some((v) => v.includes(secret)), "and is not stored");
});

test("removing a device and revoking a member name the device id in the confirmation", async () => {
  const doc = await render({ ...base, links: [link("Photos")] }, {
    "/api/devices": { devices: [
      { device_id: "this", device_name: "NAS", is_this_device: true, online: true },
      { device_id: "dev-old-1234", device_name: "Old laptop", is_this_device: false, online: false },
    ] },
    "/api/shares": { edges: [{ edge_id: "e1", group_id: "g-Photos", device_id: "dev-old-1234", state: "active" }] },
    "/api/devices/remove": { ok: true, handoffs: [] },
    "/api/share/revoke": { ok: true, handoffs: [] },
  });
  const asked = [];
  doc.defaultView.confirm = (m) => { asked.push(m); return false; };
  doc.querySelector("button[data-remove-device]").click();
  doc.querySelector("#shares-table button[data-revoke-group]").click();
  await settle();
  assert.equal(asked.length, 2);
  assert.ok(asked.every((m) => m.includes("(dev-old-1234)")), JSON.stringify(asked));
});

test("kept originals: hidden when none; one Free-up button per group with the daemon's wording", async () => {
  const none = await render(base);
  assert.equal(none.getElementById("retained-card").hidden, true);

  const doc = await render(base, {
    "/api/retained": { items: [
      { group_id: "g1", group_removed: false, path: "a.txt", size: 2048, reachable: true },
      { group_id: "g1", group_removed: false, path: "b.txt", size: 0, reachable: false },
      { group_id: "g2", group_removed: true, path: "c.txt", size: 10, reachable: true },
    ] },
    "/api/retained/free": { results: [
      { path: "a.txt", outcome: "removed", detail: "" },
      { path: "b.txt", outcome: "still_retained", detail: "" },
    ] },
  });
  assert.equal(doc.getElementById("retained-card").hidden, false);
  const table = text(doc, "retained-table");
  assert.match(table, /2\.0 KB/);
  assert.match(table, /size unknown \(the folder is not watched\)/);
  assert.match(table, /g2 \(group removed\)/);
  const buttons = doc.querySelectorAll("#retained-table button[data-free-group]");
  assert.equal(buttons.length, 2, "one per group");
  buttons[0].click();
  await settle();
  assert.deepEqual(posts(doc).map((c) => [c.path, c.body]), [["/api/retained/free", { group_id: "g1" }]]);
  assert.match(text(doc, "retained-note"), /a\.txt: freed up; b\.txt: kept: it may still be written to/);
});
