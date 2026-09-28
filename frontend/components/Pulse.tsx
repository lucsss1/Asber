import { apiSafe } from "@/lib/api";
import { PulseBand, type Day } from "@/components/PulseBand";

type PulseData = { days: number; peak: number; series: Day[] };

/**
 * Thirty days of threat activity, running under the rail on every page.
 *
 * This is the one thing on screen that is never a number you read — it is a
 * shape you recognise. A quiet fortnight and a bad Tuesday look different from
 * across the room.
 *
 * The bars carry no risk colour. Colour in this system means risk, and painting
 * most days warm would have spent the loudest ink on the least urgent thing;
 * the band reports how much moved, not how bad it is.
 */
export async function Pulse() {
  const data = await apiSafe<PulseData>("/api/dashboard/pulse", { days: "30" });
  if (!data?.series?.length) return null;

  const busiest = data.series.reduce((a, b) => (b.total > a.total ? b : a));
  return <PulseBand series={data.series} peak={Math.max(1, data.peak)} busiest={busiest} />;
}
