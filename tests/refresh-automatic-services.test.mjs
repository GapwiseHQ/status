import test from "node:test";
import assert from "node:assert/strict";
import { refreshAutomaticServices } from "../scripts/refresh-automatic-services.mjs";

test("probes at most four services concurrently and preserves manual state", async () => {
  const automatic = Array.from({ length: 9 }, (_, id) => ({ id, monitoring: "automatic" }));
  const manual = { id: "manual", monitoring: "manual", status: "degraded" };
  const unknown = { id: "unknown", monitoring: "automatic" };
  const checks = new Map(automatic.map(({ id }) => [id, { url: `https://example.test/${id}` }]));
  let active = 0;
  let maximum = 0;
  let calls = 0;
  await refreshAutomaticServices([{ services: [...automatic, manual, unknown] }], checks, async () => {
    calls++;
    maximum = Math.max(maximum, ++active);
    await new Promise((resolve) => setTimeout(resolve, 1));
    active--;
    return { status: "operational", detail: "HTTP 200" };
  }, "checked");
  assert.equal(maximum, 4);
  assert.equal(calls, 9);
  for (const service of automatic) {
    assert.equal(service.status, "operational");
    assert.equal(service.checkedAt, "checked");
    assert.equal(service.url, checks.get(service.id).url);
  }
  assert.deepEqual(manual, { id: "manual", monitoring: "manual", status: "degraded" });
  assert.equal(unknown.status, "unknown");
  assert.equal(unknown.detail, "No automated probe is configured");
});

test("handles an empty service inventory", async () => {
  await refreshAutomaticServices([], new Map(), () => assert.fail("unexpected probe"), "checked");
});
