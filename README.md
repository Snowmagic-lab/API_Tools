# ai-hands

Bring your own AI API key, and the model gets "hands" on your computer:
calculator, web search, reading web pages, using a real browser, notifications, files,
opening apps, and running commands (with your approval).

## Setup

```
python -m venv ~/.ai_hands/venv
~/.ai_hands/venv/Scripts/python -m pip install -r requirements.txt     # macOS/Linux: venv/bin/python
~/.ai_hands/venv/Scripts/python main.py
```

The virtual environment lives outside this folder so OneDrive doesn't sync its thousands of files, and it also works
when your Python refuses `pip install` (Python from `uv`, for example). `keyring` stores your API key securely and
`truststore` fixes HTTPS errors on some sites. `playwright` powers the browser tools using your installed Edge or Chrome,
so there's no extra browser to download. The app still runs without them, using plain `python main.py`.

The first run asks which API you use (Anthropic, OpenAI, Gemini, OpenRouter, or any
OpenAI-compatible server such as Ollama), the model name, and your key.
Your key shows as `*****` while you type or paste it, and setup then lists the models
your key can use so you pick one by number. Settings live in `~/.ai_hands/config.json`; the key is never written there.

In VS Code, choose the virtual environment's Python as the interpreter, then run with **Run Without Debugging** (Ctrl+F5).
The debugger pauses on exit, which looks like a freeze.

Commands while chatting: `/tools`, `/reset`, `/setup`, `/forgetkey`, `/quit`

## How it works

```
You ──► main.py ──► provider adapter ──► AI API
                        ▲     │ "call calculate(17*23)"
                        │     ▼
                   tools.run_tool()  (asks you first if the tool is risky)
                        │
                        └── result "391" sent back, loop until the AI answers
```

| File | Job |
|---|---|
| `main.py` | Chat loop and the tool-calling loop (max 15 steps per message) |
| `providers.py` | Translates between the app and each API's tool-calling format |
| `tools.py` | The AI's tools, plus the confirmation check |
| `browser.py` | The `browser_*` tools and the proxy that filters browser traffic |
| `config.py` | Provider choice and secure key storage |

## Adding a tool

```python
@tool("get_battery", "Get the laptop battery percentage.", _obj())
def get_battery():
    import psutil
    b = psutil.sensors_battery()
    return f"{b.percent}% {'charging' if b.power_plugged else 'on battery'}"
```

Set `risky=True` on anything that changes files, runs programs, sends messages or
spends money. Set `private=True` if it brings local data into the chat, and `sends_out=True`
if it can send data to any address. A clear description matters: it's how the model decides when to use the tool.

## Safety notes

- Risky tools (`write_text_file`, `open_file_or_app`, `run_command`) always ask `Allow? [y/N]`,
  and the prompt shows the full command or content.
- Reading or listing sensitive locations (SSH and cloud keys, `.env` files, browser profiles and so on) also asks first.
  That list can't catch everything, so the next rule is the real protection.
- Once the AI has seen local data in a chat, `fetch_webpage` and `open_in_browser` ask before every use,
  so a malicious page can't quietly get that data sent out. `/reset` clears this.
  Reading further parts of a page already downloaded doesn't ask, because nothing is sent.
- `fetch_webpage` and `open_in_browser` refuse local and private network addresses, including `fetch_webpage` redirects.
- The browser opens a visible window with a blank temporary profile, so the AI never gets your sign-ins.
  **Don't sign in to anything in that window**, because clicks don't ask for approval and the AI could act on your account.
  `/reset`, `/setup` and `browser_close` delete the session.
- `browser_type` asks every time and shows the field and site, because typing is how data leaves the browser.
  `browser_open` follows the same "seen local data" rule as `fetch_webpage`.
- All browser traffic goes through a local proxy that checks each connection's real IP address, so pages can't reach
  your computer or home network, even through redirects, WebSockets or a changed DNS answer.
- Browser downloads and WebRTC are turned off, and pages can't open the file picker.
- If a page moves to another site after you approve typing, nothing is typed.
- Web content is wrapped in `[UNTRUSTED CONTENT]` markers so the model treats it as data.
  This reduces prompt injection but doesn't eliminate it, which is why these approvals exist.
- Tool output is cut to 6,000 characters to keep API costs down. Long web pages are split into parts
  of about 5,000 characters, and the AI asks for the next part only if it needs it (up to 2 MB per page).

Known limits: `web_search` never asks, so a query could still pass local data to DuckDuckGo. Private data you
paste into the chat yourself doesn't trigger the approval rule. In `fetch_webpage` (not the browser), a site that
changes its DNS answer between the address check and the request could still reach a local address. Browser clicks
are never approved, so a page could trick the AI into clicking something, though with no sign-ins there's little it can do.
The browser tools read the main page only, not content inside iframes.

## Ideas for next steps

1. A GUI (Tkinter, PySide6, or a local web page) instead of the terminal
2. Streaming responses so text appears as it's written
3. More tools: clipboard, battery/CPU stats (`psutil`), media keys
4. Expose `tools.py` as an MCP server so other AI apps can use the same tools
5. A phone companion app that receives commands from the desktop app
