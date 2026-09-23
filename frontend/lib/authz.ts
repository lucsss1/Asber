/** Who is allowed in.
 *
 *  OAuth only proves *who* someone is — it does not decide whether they may
 *  use this deployment. Without an explicit allowlist, "sign in with Google"
 *  means every Google account on earth, so an empty list denies everyone
 *  rather than failing open.
 */

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
