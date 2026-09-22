import type { Metadata } from "next";

import { signIn } from "@/auth";
import { allowedEmails } from "@/lib/authz";

export const metadata: Metadata = { title: "Sign in" };

const PROVIDERS = [
  { id: "google", label: "Continue with Google", configured: () => Boolean(process.env.AUTH_GOOGLE_ID) },
  { id: "github", label: "Continue with GitHub", configured: () => Boolean(process.env.AUTH_GITHUB_ID) },
];

export default async function Login({
  searchParams,
}: {
  searchParams: Promise<{ next?: string; error?: string }>;
}) {
  const { next, error } = await searchParams;
  const available = PROVIDERS.filter((p) => p.configured());

  return (
    <div className="login">
      <div className="login-card">
        <div className="brand">
          <div className="brand-mark">A</div>
          <div>
            <div className="brand-title">Asber</div>
            <div className="brand-sub">Cyber threat watch</div>
          </div>
        </div>

        {error ? (
          <p className="login-error">
            {error === "AccessDenied"
              ? "That account is not on the allowlist for this deployment."
              : "Sign-in failed. Please try again."}
          </p>
        ) : null}

        {available.length === 0 ? (
          <p className="muted">
            No sign-in provider is configured. Set <code>AUTH_GOOGLE_ID</code> or{" "}
            <code>AUTH_GITHUB_ID</code> and restart.
          </p>
        ) : (
          available.map((provider) => (
            <form
              key={provider.id}
              action={async () => {
                "use server";
                // Only ever redirect within this site.
                const to = next?.startsWith("/") && !next.startsWith("//") ? next : "/";
                await signIn(provider.id, { redirectTo: to });
              }}
            >
              <button type="submit" className="btn btn-primary login-btn">
                {provider.label}
              </button>
            </form>
          ))
        )}

        {allowedEmails().length === 0 ? (
          <p className="login-note">
            <strong>AUTH_ALLOWED_EMAILS is empty</strong>, so every sign-in will be rejected. This
            is deliberate: an unset allowlist must not mean “anyone with an account”.
          </p>
        ) : (
          <p className="login-note">Access is limited to the accounts on this deployment’s allowlist.</p>
        )}
      </div>
    </div>
  );
}
