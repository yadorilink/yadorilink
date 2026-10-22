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

async function render(status) {
  const dom = new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true, url: "http://127.0.0.1:8484/" });
  open.push(dom);
  const json = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
  dom.window.fetch = (path) => {
    if (path === "/api/status") return json(status);
    if (path === "/api/conflicts") return json({ conflicts: [] });
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
    attention_reasons: ["peer_update_required:abc"],
    peers: [{ device_id: "abc", reachability: "PEER_REACHABILITY_CONNECTED", route_kind: "ROUTE_KIND_DIRECT", version_incompatible: true }],
  });
  assert.match(text(doc, "overall-state"), /Update required/);
  assert.doesNotMatch(text(doc, "overall-state"), /peer_update_required|can't be reached/);
  assert.match(text(doc, "connections-table"), /update required/);
  assert.doesNotMatch(text(doc, "connections-table"), /unreachable/);
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
