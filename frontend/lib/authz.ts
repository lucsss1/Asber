/** Who is allowed in.
 *
 *  OAuth only proves *who* someone is — it does not decide whether they may
 *  use this deployment. Without an explicit allowlist, "sign in with Google"
 *  means every Google account on earth, so an empty list denies everyone
 *  rather than failing open.
 */

/** Local-only escape hatch.
 *
 *  On a laptop the operating system is the access control and there is no OAuth
 *  provider to sign in with, so requiring a session would lock the dashboard
 *  behind a login that cannot be completed. It must be set deliberately: an
 *  unset value means authentication is required, and no deployment
 *  configuration in this repository sets it.
 */
export function authDisabled(): boolean {
  return process.env.AUTH_DISABLED === "true";
}

function parseList(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

export function allowedEmails(): string[] {
  return parseList(process.env.AUTH_ALLOWED_EMAILS);
}

/** Admins may trigger ingestion runs; everyone else gets a read-only dashboard. */
export function adminEmails(): string[] {
  const admins = parseList(process.env.AUTH_ADMIN_EMAILS);
  return admins.length ? admins : allowedEmails();
}

export function isAllowed(email: string | null | undefined): boolean {
  if (!email) return false;
  return allowedEmails().includes(email.toLowerCase());
}

export function isAdmin(email: string | null | undefined): boolean {
  if (!email) return false;
  return adminEmails().includes(email.toLowerCase());
}

/** Who may see the Rampart inventory.
 *
 *  Deliberately *not* isAdmin(). That function falls back to the full allowlist
 *  when AUTH_ADMIN_EMAILS is unset, which is a reasonable default for "may
 *  trigger an ingestion run" and the wrong one here: an inventory is a map of
 *  the deployment's attack surface, and it must not become readable to every
 *  allowed account because a variable was never set.
 *
 *  So this one fails closed. No AUTH_ADMIN_EMAILS, no Rampart — for anybody.
 */
export function isRampartOwner(email: string | null | undefined): boolean {
  if (!email) return false;
  const owners = parseList(process.env.AUTH_ADMIN_EMAILS);
  if (!owners.length) return false;
  return owners.includes(email.toLowerCase());
}
