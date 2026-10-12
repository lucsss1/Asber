"use server";

import { revalidatePath } from "next/cache";

import { ApiError, apiWrite } from "@/lib/api";
import { canSeeRampart } from "@/lib/rampart";

/** Server Actions carry Next's own origin check, so the inventory is never
 *  mutated by a cross-site form post. The owner check is repeated here anyway:
 *  the middleware guards the route, and an action is reachable by its own id,
 *  so "the page was protected" is not the same as "this call was". */
async function assertOwner() {
  if (!(await canSeeRampart())) throw new Error("not an environment owner");
}

export type ActionResult = { ok: true } | { ok: false; error: string };

function field(form: FormData, name: string): string | null {
  const raw = form.get(name);
  const value = typeof raw === "string" ? raw.trim() : "";
  return value === "" ? null : value;
}

function payload(form: FormData) {
  return {
    label: field(form, "label") ?? "",
    category: field(form, "category") ?? "other",
    vendor: field(form, "vendor") ?? "",
    product: field(form, "product") ?? "",
    version: field(form, "version"),
    cpe: field(form, "cpe"),
    catalogued: form.get("catalogued") === "true",
    hardware_model: field(form, "hardware_model"),
    notes: field(form, "notes"),
  };
}

/** The backend owns validation; this only turns its refusal into something the
 *  form can show without leaking a stack trace. */
async function run(fn: () => Promise<unknown>): Promise<ActionResult> {
  try {
    await fn();
    revalidatePath("/rampart");
    revalidatePath("/rampart/threats");
    revalidatePath("/");
    return { ok: true };
  } catch (e) {
    const message = e instanceof ApiError ? e.message : "Could not save the asset.";
    return { ok: false, error: message };
  }
}

export async function createAsset(_prev: ActionResult | null, form: FormData): Promise<ActionResult> {
  await assertOwner();
  return run(() => apiWrite("/api/rampart/assets", "POST", payload(form)));
}

export async function updateAsset(_prev: ActionResult | null, form: FormData): Promise<ActionResult> {
  await assertOwner();
  const id = Number(form.get("id"));
  if (!Number.isInteger(id) || id <= 0) return { ok: false, error: "Unknown asset." };
  return run(() => apiWrite(`/api/rampart/assets/${id}`, "PATCH", payload(form)));
}

export async function deleteAsset(form: FormData): Promise<void> {
  await assertOwner();
  const id = Number(form.get("id"));
  if (!Number.isInteger(id) || id <= 0) return;
  try {
    await apiWrite(`/api/rampart/assets/${id}`, "DELETE");
  } catch {
    /* Already gone, or not ours: either way there is nothing to show. */
  }
  revalidatePath("/rampart");
  revalidatePath("/rampart/threats");
  revalidatePath("/");
}
