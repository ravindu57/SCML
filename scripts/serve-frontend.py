#!/usr/bin/env python3
"""
Serve the dashboard with caching disabled.

`python3 -m http.server` sends Last-Modified but no Cache-Control, so browsers
apply heuristic caching to js/api.js. Editing a dashboard file then reloading
shows the *old* behaviour, and a plain F5 does not clear it — you need a hard
refresh, which nobody thinks to do because nothing looks broken.

That cost real time once already: a timestamp fix was verified as correct on
the server and still rendered wrong in the browser. On an exhibition machine,
where someone may tweak a page minutes before showing it, silently serving
stale JavaScript is the wrong default.

Usage:
    python3 scripts/serve-frontend.py <port> <directory>
"""

from __future__ import annotations

import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class NoCacheHandler(SimpleHTTPRequestHandler):
    """Static handler that tells browsers never to reuse a response."""

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        # The dashboard is opened from other machines on the LAN and talks to a
        # mediator on a different origin; it is a local demo tool, not a
        # production surface.
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        # One line per request is noise in the launcher log; errors still raise.
        pass


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip())
        return 2

    port = int(sys.argv[1])
    directory = sys.argv[2]

    handler = partial(NoCacheHandler, directory=directory)
    server = ThreadingHTTPServer(("0.0.0.0", port), handler)
    print(f"dashboard on :{port} (no-store) serving {directory}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
