/** Who may reach the Rampart inventory.
 *
 *  Run with `npm test` — Node's own test runner, no framework. The authz rules
 *  are pure functions of the environment, which is exactly the shape that is
 *  worth testing offline: the decision they encode is "may this account see a
 *  map of what we run", and it must not be re-derived by reading the code.
 */
import { test, describe, afterEach } from "node:test";
import assert from "node:assert/strict";

import { isAdmin, isAllowed, isRampartOwner } from "./authz.ts";

const ALLOWED = "owner@example.com";
const OTHER = "colleague@example.com";

function env(allowed?: string, admins?: string) {
  if (allowed === undefined) delete process.env.AUTH_ALLOWED_EMAILS;
  else process.env.AUTH_ALLOWED_EMAILS = allowed;
  if (admins === undefined) delete process.env.AUTH_ADMIN_EMAILS;
  else process.env.AUTH_ADMIN_EMAILS = admins;
}

afterEach(() => env(undefined, undefined));

describe("the allowlist", () => {
  test("an empty list denies everyone rather than failing open", () => {
    env("");
    assert.equal(isAllowed(ALLOWED), false);
  });

  test("an allowed address is allowed, case-insensitively", () => {
    env(`${ALLOWED},${OTHER}`);
    assert.equal(isAllowed("OWNER@Example.com"), true);
    assert.equal(isAllowed("stranger@example.com"), false);
  });
});

describe("isAdmin keeps its fallback", () => {
  test("without AUTH_ADMIN_EMAILS every allowed account is an admin", () => {
    env(`${ALLOWED},${OTHER}`);
    assert.equal(isAdmin(OTHER), true);
  });

  test("with AUTH_ADMIN_EMAILS only the named accounts are", () => {
    env(`${ALLOWED},${OTHER}`, ALLOWED);
    assert.equal(isAdmin(ALLOWED), true);
    assert.equal(isAdmin(OTHER), false);
  });
});

describe("isRampartOwner fails closed", () => {
  test("THE NEGATIVE CASE: an allowlisted non-admin is not an environment owner", () => {
    env(`${ALLOWED},${OTHER}`, ALLOWED);
    assert.equal(isAllowed(OTHER), true, "precondition: the account may use the dashboard");
    assert.equal(isRampartOwner(OTHER), false, "but it must not reach the inventory");
    assert.equal(isRampartOwner(ALLOWED), true);
  });

  test("without AUTH_ADMIN_EMAILS nobody owns an environment, not even the allowlist", () => {
    env(`${ALLOWED},${OTHER}`);
    assert.equal(isAdmin(ALLOWED), true, "isAdmin still falls back");
    assert.equal(isRampartOwner(ALLOWED), false, "isRampartOwner does not");
  });

  test("an absent address is never an owner", () => {
    env(`${ALLOWED}`, `${ALLOWED}`);
    assert.equal(isRampartOwner(null), false);
    assert.equal(isRampartOwner(undefined), false);
    assert.equal(isRampartOwner(""), false);
  });

  test("addresses are compared case-insensitively and trimmed", () => {
    env(ALLOWED, ` ${ALLOWED.toUpperCase()} `);
    assert.equal(isRampartOwner(ALLOWED), true);
  });
});
