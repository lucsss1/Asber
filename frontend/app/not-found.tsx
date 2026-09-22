import Link from "next/link";

export default function NotFound() {
  return (
    <div className="empty">
      <h1>Not found</h1>
      <p className="muted">This entity is not tracked locally and was not found upstream.</p>
      <Link href="/" className="btn">Back to dashboard</Link>
    </div>
  );
}
