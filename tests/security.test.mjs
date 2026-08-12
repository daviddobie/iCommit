import assert from "node:assert/strict";
import test from "node:test";

import {
  hashPassword,
  signAccessToken,
  verifyAccessToken,
  verifyPassword,
} from "../dist/security.js";

test("password hashes verify only with the original password", async () => {
  const encoded = await hashPassword("a-longer-commitment-password");
  assert.equal(await verifyPassword("a-longer-commitment-password", encoded), true);
  assert.equal(await verifyPassword("not-the-same-password", encoded), false);
});

test("access tokens are signed, scoped to a user, and expire", () => {
  const now = 1_700_000_000_000;
  const token = signAccessToken(42, "a-strong-test-secret", now);

  assert.deepEqual(verifyAccessToken(token, "a-strong-test-secret", now), {
    userId: 42,
    exp: 1_700_604_800,
  });
  assert.equal(verifyAccessToken(token, "different-secret", now), null);
  assert.equal(verifyAccessToken(token, "a-strong-test-secret", now + 8 * 24 * 60 * 60 * 1000), null);
});
