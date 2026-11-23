"""Exercise the built tool at a project subpath in Chromium, with offline captures and simulated DoH resolvers."""
import base64
import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from urllib.parse import urlparse, parse_qs
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "web" / "config.json").read_text())


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def qname(dns_param):
    raw = base64.urlsafe_b64decode(dns_param + "=" * (-len(dns_param) % 4))
    i, labels = 12, []
    while raw[i]:
        labels.append(raw[i + 1:i + 1 + raw[i]].decode())
        i += raw[i] + 1
    return ".".join(labels).lower(), raw[12:i + 5]


def response(question, ip=None, rcode=0):
    header = bytes([0, 0, 0x81, 0x80 | rcode, 0, 1, 0, 1 if ip else 0, 0, 0, 0, 0])
    answer = bytes([0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, *map(int, ip.split("."))]) if ip else b""
    return header + question + answer


def fake_resolvers(page):
    """CIRA refuses browser requests; Cloudflare blocks 'bad.example' with 0.0.0.0; Quad9 with NXDOMAIN."""
    urls = {r["url"]: r["id"] for r in CONFIG["resolvers"]}

    def handle(route):
        url = route.request.url
        if "127.0.0.1" in url:
            return route.continue_()
        base = url.split("?")[0]
        rid = urls.get(base)
        if not rid:
            return route.abort()
        if rid.startswith("cira"):
            return route.fulfill(status=200, body=b"", headers={})  # no CORS header: browser rejects it
        name, question = qname(parse_qs(urlparse(url).query)["dns"][0])
        bad = name == "bad.example"
        if rid == "cloudflare-security" and bad:
            body = response(question, "0.0.0.0")
        elif rid == "quad9" and bad:
            body = response(question, rcode=3)
        else:
            body = response(question, "198.51.100.7")
        route.fulfill(status=200, body=body, headers={"Content-Type": "application/dns-message", "Access-Control-Allow-Origin": "*"})
    page.route("**/*", handle)


def main():
    screenshots = ROOT / "browser-checks"
    screenshots.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        site = Path(temporary) / "shieldcheck"
        shutil.copytree(ROOT / "dist", site)
        shutil.rmtree(site / "data", ignore_errors=True)
        for now in ("2026-11-23T12:00:00Z", "2026-11-23T18:00:00Z"):
            subprocess.run(["node", str(ROOT / "scripts/capture.mjs"), "--fixtures", str(ROOT / "tests/fixtures/sim"),
                            "--cache", str(Path(temporary) / "cache"), "--out", str(site / "data"), "--now", now],
                           check=True, capture_output=True)
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=temporary))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page(viewport={"width": 1280, "height": 1000})
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                fake_resolvers(page)
                page.goto(f"http://127.0.0.1:{server.server_port}/shieldcheck/")
                page.wait_for_selector("#scoreboard .bars")

                assert page.locator("#capture option").count() == 2
                assert "Checked" in page.locator("#capture-note").inner_text()
                assert page.locator("#scoreboard .track").count() == len([r for r in CONFIG["resolvers"] if r.get("baseline")])
                assert "CIRA Canadian Shield · Protected blocked the most" in page.locator("#score-lede").inner_text()
                assert "1 control blocked" in page.locator("#scoreboard").inner_text()
                assert page.locator("#domains tbody tr").count() == 25
                assert page.locator("#domains a").count() == 0, "threat domains must not be links"

                page.select_option("#filter", "missed")
                assert page.locator("#domains tbody tr").count() == 5
                page.select_option("#filter", "controls")
                assert page.locator("#domains tbody tr").count() == len(CONFIG["controls"])
                page.select_option("#filter", "all")
                page.fill("#search", "payload1")
                assert page.locator("#domains tbody tr").count() == 2  # payload1 and payload10

                page.select_option("#capture", "2026-11-23T12")
                page.wait_for_function("location.search.includes('capture=2026-11-23T12')")

                # Live check: CIRA unreachable from the browser, others classify.
                page.fill("#live-input", "bad.example\nhttps://good.example/login, not a domain!!")
                page.click("#live-form button[type=submit]")
                page.wait_for_function("document.querySelector('#live-status').textContent.startsWith('Checked')")
                status = page.locator("#live-status").inner_text()
                assert "Not reachable from your browser: CIRA" in status and "Skipped 1 entry that isn’t" in status, status
                bad = page.locator("#live tbody tr").nth(0).locator("td").all_inner_texts()
                good = page.locator("#live tbody tr").nth(1).locator("td").all_inner_texts()
                ids = [r["id"] for r in CONFIG["resolvers"] if r.get("baseline")]
                assert bad[0] == "bad.example" and good[0] == "good.example"
                assert bad[1 + ids.index("cloudflare-security")] == "■" and bad[1 + ids.index("quad9")] == "■"
                assert good[1 + ids.index("quad9")] == "·" and bad[1 + ids.index("cira-protected")] == "!"

                page.screenshot(path=str(screenshots / "desktop.png"), full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                page.screenshot(path=str(screenshots / "mobile.png"), full_page=True)
                assert not errors, errors
                browser.close()
            print("Browser checks passed: subpath, captures, scoreboard, filters, safe text, live check and mobile layout")
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
