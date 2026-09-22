import { IconSearch } from "@/components/icons";

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
      </form>
    </div>
  );
}
