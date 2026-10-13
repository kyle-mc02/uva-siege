"""Headless browser smoke test — the first time the UI actually renders.

Launches a real `siege` server and drives Chromium: load the page, import an
nmap scan, click a host, add a finding, open /wall. Fails on ANY uncaught JS
error (the real "the UI is broken" signal) and asserts the key flows populate.

Skips cleanly when Playwright or the browser isn't installed, so the normal
suite still runs headless-free. Install with: pip install playwright &&
python -m playwright install chromium   (and `install-deps` if the browser
won't launch for missing system libraries).
"""

from __future__ import annotations

import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"server did not come up at {url}")


@pytest.fixture()
def server(tmp_path):
    port = _free_port()
    db = tmp_path / "ui.sqlite"
    proc = subprocess.Popen(
        ["siege", "--db", str(db), "--port", str(port), "--evidence-dir", str(tmp_path / "ev")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _wait_http(f"http://127.0.0.1:{port}/")
        token = Path(str(db) + ".token").read_text().strip()
        yield f"http://127.0.0.1:{port}", token
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture()
def browser():
    try:
        with sync_playwright() as pw:
            try:
                b = pw.chromium.launch(headless=True)
            except Exception as exc:  # browser/libs missing
                pytest.skip(f"chromium won't launch ({type(exc).__name__}); run `playwright install-deps`")
            yield b
            b.close()
    except Exception as exc:
        pytest.skip(f"playwright unavailable: {exc}")


def _page(browser):
    # bypass_csp lets Playwright's instrumentation (wait_for_function uses eval)
    # drive the page. Our strict `script-src 'self'` CSP — which blocks that eval
    # — is real and asserted in test_api; our own scripts are external files with
    # no eval/inline, so they run fine under it. The pageerror listener still
    # catches any uncaught exception in our code.
    ctx = browser.new_context(bypass_csp=True)
    page = ctx.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))  # uncaught JS exceptions
    return page, errors


def test_operator_ui_renders_and_flows(server, browser):
    base, token = server
    page, errors = _page(browser)

    page.goto(f"{base}/?token={token}")
    # Engagement name loads from the API (proves fetch + auth + render).
    page.wait_for_function("document.getElementById('engagement').textContent === 'ui'", timeout=10000)
    # Token must be stripped from the address bar after first load.
    assert "token=" not in page.url

    # Import an nmap scan through the real file input + submit.
    page.set_input_files("#import-form input[type=file]", str(FIXTURES / "deepscan.xml"))
    page.click("#import-form button")
    page.wait_for_function("document.getElementById('status').textContent.includes('imported')", timeout=10000)

    # Cytoscape actually rendered host nodes.
    host_count = page.evaluate("() => cy.nodes(\"node[kind='host']\").length")
    assert host_count == 2

    # Click a host node on the canvas (computed from its rendered position) and
    # assert the detail panel opens and populates.
    coords = page.evaluate(
        """() => {
            const n = cy.nodes("node[kind='host']");
            const p = n[0].renderedPosition();
            const r = document.getElementById('graph').getBoundingClientRect();
            return {x: r.left + p.x, y: r.top + p.y};
        }"""
    )
    page.mouse.click(coords["x"], coords["y"])
    page.wait_for_selector("#detail:not([hidden])", timeout=5000)
    assert page.inner_text("#d-title").strip() != ""
    page.wait_for_function("document.querySelectorAll('#d-services tr').length > 0", timeout=5000)

    # Set operator identity, add a finding, assert it shows with the dropdown.
    page.fill("#operator", "smoke-op")
    page.fill("#finding-form input[name=title]", "Smoke finding")
    page.select_option("#finding-form select[name=severity]", "high")
    page.click("#finding-form button")
    page.wait_for_function(
        "[...document.querySelectorAll('#d-findings li')].some(li => li.textContent.includes('Smoke finding'))",
        timeout=5000,
    )

    assert errors == [], f"uncaught JS errors in operator UI: {errors}"
    page.context.close()


def test_wall_renders(server, browser):
    base, token = server
    page, errors = _page(browser)

    # Seed one host so the wall has something to draw.
    page.goto(f"{base}/?token={token}")
    page.wait_for_function("typeof cy !== 'undefined' && cy !== null", timeout=10000)
    page.set_input_files("#import-form input[type=file]", str(FIXTURES / "deepscan.xml"))
    page.click("#import-form button")
    page.wait_for_function("document.getElementById('status').textContent.includes('imported')", timeout=10000)

    page.goto(f"{base}/wall?token={token}")
    page.wait_for_function("document.querySelectorAll('#wall-stats .stat').length === 4", timeout=10000)
    page.wait_for_function("document.getElementById('wall-title').textContent === 'ui'", timeout=5000)
    assert errors == [], f"uncaught JS errors on /wall: {errors}"
    page.context.close()
