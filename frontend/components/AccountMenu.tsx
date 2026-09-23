import { signOut } from "@/auth";

export function AccountMenu({ user }: { user: { email?: string | null; admin?: boolean } }) {
  return (
    <div className="account">
      <span className="account-email" title={user.email ?? ""}>
        {user.email}
      </span>
      {user.admin ? <span className="account-role">admin</span> : null}
      <form
        action={async () => {
          "use server";
          await signOut({ redirectTo: "/login" });
        }}
      >
        <button type="submit" className="btn btn-ghost">
          Sign out
        </button>
      </form>
    </div>
  );
}
