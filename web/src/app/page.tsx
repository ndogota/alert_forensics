import { Console } from "./components/Console";
import { loadMatrix, loadRecordings } from "./lib/load";

// The one page. Both sources are read at build time by lib/load.ts and
// inlined into the static HTML; the client components render them and fetch
// nothing.
export default async function HomePage() {
  const [matrix, recordings] = await Promise.all([loadMatrix(), loadRecordings()]);
  return <Console matrix={matrix} recordings={recordings} />;
}
