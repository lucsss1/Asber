import { IconSearch } from "@/components/icons";
import { PaletteHint } from "@/components/PaletteHint";

/** Plain GET form — global search needs no client JavaScript. */
export function SearchBox() {
  return (
    <div className="topbar">
      <form className="searchfield" action="/search" method="get" role="search">
        <IconSearch size={15} />
        <input
          type="search"
          name="q"
          placeholder="Search a CVE, vendor, product, actor or technique…"
          aria-label="Search"
          maxLength={200}
        />
        <PaletteHint />
      </form>
    </div>
  );
}
