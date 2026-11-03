"""Real browser control, for pages that need JavaScript or clicking.

Importing this module adds the browser_* tools to the registry. Playwright is
only needed once one of them runs, and it drives the Edge or Chrome already on
this computer.

Safety design:
- Every session is a blank temporary profile, so the AI never gets your sign-ins.
- All browser traffic goes through a small local proxy that checks the real IP
  address of each connection. A filter inside the browser isn't enough, because
  redirects get past it (tested with Playwright 1.64).
- Clicking is free, but typing always asks, since typing is how data leaves.
"""
import atexit
import functools
import math
import os
import re
import select
import socket
import socketserver
import threading
import urllib.parse

import tools
from tools import _check_url, _obj, _split_pages, _untrusted, tool

TEXT_CHARS = 3000      # per part, leaving room for the controls list inside the tool output limit
CONTROLS_PER_PART = 30
LABEL_CHARS = 50

_session = {"pw": None, "browser": None, "context": None, "proxy": None, "view": None}

_READ_PAGE = """() => {
  document.querySelectorAll('[data-aih]').forEach(e => e.removeAttribute('data-aih'));
  const wanted = 'a[href],button,input:not([type=hidden]):not([type=file]),select,textarea,summary,' +
                 '[role=button],[role=link],[role=tab],[role=menuitem],[role=checkbox],[onclick],[contenteditable=true]';
  const controls = [];
  for (const e of document.querySelectorAll(wanted)) {
    const box = e.getBoundingClientRect(), style = getComputedStyle(e);
    if (box.width < 1 || box.height < 1 || style.visibility === 'hidden' || style.display === 'none') continue;
    const isButton = ['submit', 'button', 'reset'].includes(e.type);
    const hints = [e.name, e.id, e.autocomplete].join(' ');
    controls.push({
      kind: e.getAttribute('role') || (e.tagName === 'INPUT' ? e.type + ' field' : e.tagName.toLowerCase()),
      label: e.getAttribute('aria-label') || e.innerText || (isButton ? e.value : '') || e.placeholder || e.name || e.title || '',
      secret: e.type === 'password' || /passw|cc-|card|cvv|cvc/i.test(hints),
    });
    e.setAttribute('data-aih', controls.length);
  }
  return {url: location.href, title: document.title, text: document.body ? document.body.innerText : '', controls};
}"""


# ---------------------------------------------------------------- filtering proxy
class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(30)
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 65536:
            chunk = client.recv(65536)
            if not chunk:
                return
            head += chunk
        header_block, _, body = head.partition(b"\r\n\r\n")
        lines = header_block.split(b"\r\n")
        method, target, version = lines[0].decode("latin-1").split(" ", 2)
        tunnel = method == "CONNECT"
        parts = urllib.parse.urlsplit("//" + target if tunnel else target)
        if not tunnel and parts.scheme != "http":
            return self._refuse(client)
        server = self._connect(parts.hostname, parts.port or (443 if tunnel else 80))
        if server is None:
            return self._refuse(client)
        with server:
            if tunnel:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if body:
                    server.sendall(body)
            else:
                # One request per connection, or a reused connection could carry a request for another host.
                path = parts.path or "/"
                path += f"?{parts.query}" if parts.query else ""
                kept = [h for h in lines[1:] if not h.lower().startswith((b"connection:", b"proxy-connection:"))]
                first = f"{method} {path} {version}".encode("latin-1")
                server.sendall(b"\r\n".join([first, *kept, b"Connection: close"]) + b"\r\n\r\n" + body)
            self._relay(client, server)

    @staticmethod
    def _connect(host, port):
        # Connects to the exact address that was checked, so the host can't change its DNS answer afterwards.
        try:
            # IPv4 first with a short wait, or an IPv6 address that doesn't answer stalls the whole page.
            for ip in sorted(tools._public_ips(host, port), key=lambda ip: ":" in ip):
                try:
                    server = socket.create_connection((ip, port), timeout=5)
                    server.settimeout(30)
                    return server
                except OSError:
                    continue
        except (ValueError, OSError):
            pass
        return None

    @staticmethod
    def _refuse(client):
        message = b"ai-hands blocked this address because it is local, private or unreachable."
        client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                       b"Content-Length: " + str(len(message)).encode() + b"\r\n\r\n" + message)

    @staticmethod
    def _relay(a, b):
        while True:
            ready, _, _ = select.select([a, b], [], [], 120)
            if not ready:
                return
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                (b if source is a else a).sendall(data)

    def finish(self):
        self.request.close()


class _Proxy(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # browsers drop connections all the time, which isn't worth printing into the chat


# ---------------------------------------------------------------- browser session
def _launch(pw, proxy_port):
    settings = {
        "headless": bool(os.environ.get("AIHANDS_BROWSER_HEADLESS")),  # visible by default, so you can watch it
        "chromium_sandbox": True,
        "proxy": {"server": f"http://127.0.0.1:{proxy_port}", "bypass": "<-loopback>"},
        "args": ["--proxy-bypass-list=<-loopback>", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
    }
    errors = []
    for channel in ("msedge", "chrome", None):
        try:
            return pw.chromium.launch(channel=channel, **settings)
        except Exception as e:
            errors.append(f"{channel or 'chromium'}: {str(e).splitlines()[0]}")
    raise RuntimeError("Couldn't start a browser. Tell the user to install Edge or Chrome, or to run: "
                       f"python -m playwright install chromium. Details: {'; '.join(errors)}")


def _start():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError("Browser control isn't installed. Tell the user to run: "
                           "pip install -r requirements.txt") from None
    if not _session["proxy"]:
        _session["proxy"] = _Proxy(("127.0.0.1", 0), _ProxyHandler)
        threading.Thread(target=_session["proxy"].serve_forever, daemon=True).start()
        atexit.register(close_browser)
    if not _session["pw"]:
        _session["pw"] = sync_playwright().start()
    _session["browser"] = _launch(_session["pw"], _session["proxy"].server_address[1])
    _session["context"] = _session["browser"].new_context(accept_downloads=False, service_workers="block")
    # Without a listener, a page could open the system's file picker.
    _session["context"].on("page", lambda page: page.on("filechooser", lambda chooser: None))
    # WebRTC sends traffic outside the proxy, and the AI has no use for video calls.
    _session["context"].add_init_script("delete window.RTCPeerConnection; delete window.webkitRTCPeerConnection;")


def _current_page():
    """The newest open tab, starting the browser again if you closed it."""
    if not _session["browser"] or not _session["browser"].is_connected():
        _session["view"] = None
        _start()
    try:
        pages = _session["context"].pages
    except Exception:
        pages = []
    return pages[-1] if pages else _session["context"].new_page()


def close_browser():
    for name in ("browser", "pw"):
        try:
            if _session[name]:
                _session[name].close() if name == "browser" else _session[name].stop()
        except Exception:
            pass
        _session[name] = None
    _session["context"] = _session["view"] = None


def _settle(page):
    try:
        page.wait_for_load_state("domcontentloaded", timeout=15000)
        page.wait_for_load_state("networkidle", timeout=3000)
    except Exception:
        pass  # many pages never go fully quiet, so read what has loaded so far


def _short_errors(fn):
    # Playwright errors include a long call log, and only the first line helps the model.
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if type(e).__module__.startswith("playwright"):
                return f"Error: {str(e).splitlines()[0]}"
            raise
    return wrapped


def _show(page, number=1, status=None):
    """Read the current tab and format one part of it for the model."""
    if number == 1 or not _session["view"]:
        data = page.evaluate(_READ_PAGE)
        if urllib.parse.urlsplit(data["url"]).scheme not in ("http", "https"):
            _session["view"] = None
            return f"Error: the page couldn't load, or it's an address the browser tools don't read ({data['url'][:100]})."
        _session["view"] = {"url": data["url"], "title": data["title"], "text": _split_pages(data["text"], TEXT_CHARS),
                            "controls": data["controls"]}
    return _format_view(number, status)


def _label(control):
    return re.sub(r"\s+", " ", control["label"]).strip()[:LABEL_CHARS]


def _site(url):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme, parts.netloc


def _format_view(number, status):
    view = _session["view"]
    controls = view["controls"]
    parts = max(len(view["text"]), math.ceil(len(controls) / CONTROLS_PER_PART), 1)
    if number > parts:
        return f"Error: this page only has {parts} part(s)."
    lines = [f"Title: {view['title'][:200]}", view["text"][number - 1] if number <= len(view["text"]) else ""]
    first = (number - 1) * CONTROLS_PER_PART
    shown = controls[first:first + CONTROLS_PER_PART]
    if shown:
        lines.append("\nControls (use the number with browser_click or browser_type):")
    for i, c in enumerate(shown, first + 1):
        lines.append(f"[{i}] {c['kind']}: {_label(c)}")
    notes = []
    if status and status >= 400:
        notes.append(f"The server answered HTTP {status}.")
    if parts > 1:
        notes.append(f"Part {number} of {parts}.")
    if number < parts:
        notes.append(f"Use browser_read with page={number + 1} for the next part.")
    note = f"\n[{' '.join(notes)}]" if notes else ""
    return _untrusted(view["url"][:200], "\n".join(lines)) + note


def _element(page, element):
    number = int(element)
    locator = page.locator(f'[data-aih="{number}"]').first
    if not locator.count():
        raise ValueError(f"element {number} isn't on the page any more. Use browser_read for the current list.")
    return locator


def _typing_reason(args):
    """Tells the user which field and site the text is going to."""
    view = _session["view"] or {}
    target = view.get("url", "the current page")
    try:
        control = view["controls"][int(args.get("element")) - 1]
        field = _label(control)
        warning = " This looks like a password or payment field!" if control["secret"] else ""
    except (KeyError, IndexError, TypeError, ValueError):
        field, warning = "an unknown field", ""
    return f"this text goes into {field!r} on {target[:200]}, and the site can read it.{warning}"


# ---------------------------------------------------------------- tools
@tool("browser_open",
      "Open a URL in a real browser and return its text and a numbered list of controls. Use this when fetch_webpage "
      "returns little text because the page needs JavaScript, or when you need to click or fill things in. "
      "It's slower than fetch_webpage. The browser has a blank profile and isn't signed in to anything.",
      _obj({"url": {"type": "string", "description": "Full http(s) URL"}}, ["url"]), sends_out=True)
@_short_errors
def browser_open(url):
    _check_url(url)
    page = _current_page()
    response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
    _settle(page)
    return _show(page, status=response.status if response else None)


@tool("browser_read",
      "Read the page open in the browser again. Page 1 reads it fresh. Long pages are split into parts, "
      "and the result says which part you have.",
      _obj({"page": {"type": "integer", "description": "Which part to read, starting at 1 (the default)"}}))
@_short_errors
def browser_read(page=1):
    number = int(page)
    if number < 1:
        return "Error: page must be 1 or higher."
    if not _session["browser"]:
        return "Error: no page is open. Use browser_open first."
    return _show(_current_page(), number)


@tool("browser_click",
      "Click a control from the numbered list in the latest browser result, then return the page as it is afterwards.",
      _obj({"element": {"type": "integer", "description": "The control's number"}}, ["element"]))
@_short_errors
def browser_click(element):
    if not _session["browser"]:
        return "Error: no page is open. Use browser_open first."
    page = _current_page()
    _element(page, element).click(timeout=5000)
    page.wait_for_timeout(500)  # gives a navigation or new tab time to begin
    page = _current_page()
    _settle(page)
    return _show(page)


@tool("browser_type",
      "Type text into a field from the numbered list in the latest browser result. The user must approve every use. "
      "Set submit to true to press Enter afterwards. Never type passwords or payment details: ask the user to do that.",
      _obj({"element": {"type": "integer", "description": "The field's number"},
            "text": {"type": "string"},
            "submit": {"type": "boolean", "description": "Press Enter after typing"}}, ["element", "text"]),
      risky=True, why=_typing_reason)
@_short_errors
def browser_type(element, text, submit=False):
    if not _session["browser"]:
        return "Error: no page is open. Use browser_open first."
    # The user approved typing on the site they were shown, so a page that has moved on since then doesn't get the text.
    # Ask the page itself: Playwright's page.url and tab list don't update while the app waits at the approval prompt.
    _current_page().evaluate("0")
    page = _current_page()
    live_url = page.evaluate("location.href")
    view = _session["view"]
    if not view or _site(live_url) != _site(view["url"]):
        return f"Error: the page changed to {live_url[:200]} before typing, so nothing was typed. Use browser_read to check it."
    field = _element(page, element)
    field.fill(text, timeout=5000)
    if submit:
        field.press("Enter", timeout=5000)
        page.wait_for_timeout(500)
        page = _current_page()
        _settle(page)
    return _show(page)


@tool("browser_back", "Go back to the previous page in the browser.", _obj())
@_short_errors
def browser_back():
    if not _session["browser"]:
        return "Error: no page is open. Use browser_open first."
    page = _current_page()
    page.go_back(wait_until="domcontentloaded", timeout=30000)
    _settle(page)
    return _show(page)


@tool("browser_close", "Close the browser and delete everything from this browser session.", _obj())
def browser_close():
    close_browser()
    return "Browser closed."
