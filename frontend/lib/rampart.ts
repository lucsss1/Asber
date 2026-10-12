import { auth } from "@/auth";
import { authDisabled, isRampartOwner } from "@/lib/authz";

export type AssetCategory =
  | "firewall" | "switch" | "storage" | "hypervisor" | "os" | "application" | "other";

export interface Asset {
  id: number;
  label: string;
  category: AssetCategory;
  vendor: string;
  product: string;
  version: string | null;
  cpe: string | null;
  catalogued: boolean;
  hardware_model: string | null;
  notes: string | null;
}

export interface EnvironmentView {
  id: number;
  name: string;
  assets: Asset[];
  asset_limit: number;
  counts: { affected: number; possibly_affected: number; not_affected: number };
}

export interface Match {
  cve_id: string;
  asset_id: number;
  state: "affected" | "possibly_affected" | "not_affected";
  method: string;
  confidence: string;
  evidence: string | null;
  exposure: number;
}

export const CATEGORIES: { value: AssetCategory; label: string }[] = [
  { value: "firewall", label: "Firewall" },
  { value: "switch", label: "Switch / router" },
  { value: "storage", label: "Storage" },
  { value: "hypervisor", label: "Hypervisor" },
  { value: "os", label: "Operating system" },
  { value: "application", label: "Application" },
  { value: "other", label: "Other" },
];

export const STATE_LABELS: Record<Match["state"], string> = {
  affected: "Affected",
  possibly_affected: "Possibly affected",
  not_affected: "Not affected",
};

/** Whether this request may see the inventory at all.
 *
 *  The middleware already refuses non-owners, so this is not the access
 *  control — it is what stops the navigation offering a link that would 404,
 *  and what keeps the Overview card off a page it does not belong on.
 */
export async function canSeeRampart(): Promise<boolean> {
  if (authDisabled()) return true;
  const session = await auth();
  return isRampartOwner(session?.user?.email);
}
