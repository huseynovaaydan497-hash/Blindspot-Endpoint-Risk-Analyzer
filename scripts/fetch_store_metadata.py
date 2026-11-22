"""
Fill fixtures/store_cache.json with Chrome Web Store data for real extensions.

Owner: C (with A). Run BEFORE the demo, on a machine with internet:

    python scripts/fetch_store_metadata.py <extension_id> [<extension_id> ...]
    python scripts/fetch_store_metadata.py --from-folder samples/real

The Chrome Web Store has no official public API, so this parses the public
detail page. Page markup changes; if a field cannot be parsed it is left
empty and printed, so you can fill it in by hand from the store page.
Results are cached so the demo itself runs fully offline.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blindspot.contract import FIXTURES  # noqa: E402
from blindspot.pipeline import discover_extensions  # noqa: E402
from blindspot.analyzer.manifest import load_manifest  # noqa: E402

STORE_URL = "https://chromewebstore.google.com/detail/{id}"
CACHE = FIXTURES / "store_cache.json"


def fetch(ext_id: str) -> dict:
    req = urllib.request.Request(STORE_URL.format(id=ext_id), headers={"User-Agent": "Mozilla/5.0 Blindspot"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            html = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"in_store": False}
        raise
    entry: dict = {"in_store": True}

    users = re.search(r"([\d,.]+)\s*(?:\+\s*)?users", html, re.I)
    if users:
        entry["users"] = int(re.sub(r"[^\d]", "", users.group(1)) or 0)
    updated = re.search(r"Updated</div>\s*<div[^>]*>([^<]+)<", html)
    if updated:
        try:
            entry["last_updated"] = datetime.strptime(updated.group(1).strip(), "%B %d, %Y").date().isoformat()
        except ValueError:
            entry["last_updated_raw"] = updated.group(1).strip()
    rating = re.search(r"([0-5](?:\.\d)?) out of 5", html)
    if rating:
        entry["rating"] = float(rating.group(1))
    title = re.search(r"<title>([^<]+?)\s*-\s*Chrome Web Store</title>", html)
    if title:
        entry["name"] = title.group(1).strip()
    publisher = re.search(r'"author"\s*:\s*\{[^}]*"name"\s*:\s*"([^"]+)"', html)
    if publisher:
        entry["publisher"] = publisher.group(1)
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ids", nargs="*")
    parser.add_argument("--from-folder")
    args = parser.parse_args()

    ids = list(args.ids)
    if args.from_folder:
        ids += [load_manifest(d)["id"] for d in discover_extensions(args.from_folder)]
    if not ids:
        parser.print_help()
        return 1

    cache = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {"extensions": {}}
    for ext_id in ids:
        try:
            entry = fetch(ext_id)
        except Exception as exc:  # noqa: BLE001
            print(f"{ext_id}: failed ({exc})")
            continue
        missing = [k for k in ("users", "last_updated", "publisher") if k not in entry and entry.get("in_store")]
        cache["extensions"][ext_id] = {**cache["extensions"].get(ext_id, {}), **entry}
        print(f"{ext_id}: {entry}" + (f"  -- fill by hand: {missing}" if missing else ""))
    CACHE.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    print("Saved", CACHE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
