"""Settings and API key storage.

Non-secret settings (provider, model, base URL) go in ~/.ai_hands/config.json.
The API key goes in the OS secure store via `keyring` (Windows Credential
Manager, macOS Keychain, Linux Secret Service). If keyring isn't installed,
the key is read from the AIHANDS_API_KEY environment variable or asked for
each session — it is never written to a plain text file.
"""
import getpass
import json
import os
import subprocess
import sys
from pathlib import Path

from providers import APIError, list_models

CONFIG_DIR = Path.home() / ".ai_hands"
CONFIG_FILE = CONFIG_DIR / "config.json"
KEYRING_SERVICE = "ai-hands"

try:
    import keyring  # pip install keyring
except ImportError:
    keyring = None

PROVIDERS = {
    "1": {"name": "anthropic", "label": "Anthropic (Claude)",
          "base_url": "https://api.anthropic.com", "key_prefix": "sk-ant-"},
    "2": {"name": "openai", "label": "OpenAI",
          "base_url": "https://api.openai.com/v1", "key_prefix": "sk-"},
    "3": {"name": "openai", "label": "Google Gemini",
          "base_url": "https://generativelanguage.googleapis.com/v1beta/openai", "key_prefix": "AIza"},
    "4": {"name": "openai", "label": "OpenRouter (many models, one key)",
          "base_url": "https://openrouter.ai/api/v1", "key_prefix": "sk-or-"},
    "5": {"name": "openai", "label": "Other OpenAI-compatible (Groq, Ollama, LM Studio...)",
          "base_url": "", "key_prefix": ""},
}

_session_keys = {}  # keys typed this session, when keyring isn't available


# ---------------------------------------------------------------- config file
def load_config():
    if not CONFIG_FILE.exists():
        return None
    try:
        cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    # A model name never has spaces or wildcards — if it does, setup went wrong.
    if not cfg.get("model") or any(c in cfg["model"] for c in " *"):
        print(f"The saved model name '{cfg.get('model')}' isn't valid, let's redo setup.")
        return None
    return cfg


def save_config(cfg):
    CONFIG_DIR.mkdir(exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- secret input
def _windows_clipboard():
    r = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
                       capture_output=True, text=True)
    return r.stdout.strip()


def ask_secret(prompt):
    """Like getpass, but shows a * for each character so you can see typing/pasting works."""
    if os.name != "nt" or not sys.stdin.isatty():
        return getpass.getpass(prompt)
    import msvcrt
    print(prompt, end="", flush=True)
    chars = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            print()
            return "".join(chars)
        if ch == "\x03":                       # Ctrl+C
            print()
            raise KeyboardInterrupt
        if ch in ("\x00", "\xe0"):             # arrow / function keys send 2 codes
            msvcrt.getwch()
            continue
        if ch == "\x08":                       # Backspace
            if chars:
                chars.pop()
                print("\b \b", end="", flush=True)
            continue
        if ch == "\x16":                       # Ctrl+V in the classic console window
            text = _windows_clipboard()
            chars.extend(text)
            print("*" * len(text), end="", flush=True)
            continue
        chars.append(ch)
        print("*", end="", flush=True)


def _clean_key(key):
    return key.strip().strip('"').strip("'").strip()


# ---------------------------------------------------------------- key storage
def _key_id(cfg):
    return f"{cfg['provider']}|{cfg['base_url']}"


def _prompt_key(cfg, prefix=""):
    while True:
        key = _clean_key(ask_secret("Paste your API key (blank for local servers), then press Enter: "))
        if not key:
            return "none"
        print(f"Got a key ending in ...{key[-4:]} ({len(key)} characters).")
        if prefix and not key.startswith(prefix):
            print(f"Heads up: keys for this provider usually start with '{prefix}'.")
            if input("Use it anyway? [y/N] ").strip().lower() not in ("y", "yes"):
                continue
        return key


def _store_key(cfg, key):
    _session_keys[_key_id(cfg)] = key
    if keyring and key != "none":
        try:
            keyring.set_password(KEYRING_SERVICE, _key_id(cfg), key)
            print("Key saved to your OS secure storage.")
            return
        except Exception as e:
            print(f"(Couldn't save to secure storage: {e})")
    if key != "none":
        print("(Run `pip install keyring` to save the key securely. For now it's kept for this session only.)")


def get_api_key(cfg):
    if os.environ.get("AIHANDS_API_KEY"):
        return os.environ["AIHANDS_API_KEY"]
    if _key_id(cfg) in _session_keys:
        return _session_keys[_key_id(cfg)]
    if keyring:
        try:
            key = keyring.get_password(KEYRING_SERVICE, _key_id(cfg))
            if key:
                return key
        except Exception:
            pass
    key = _prompt_key(cfg)
    _store_key(cfg, key)
    return key


def forget_api_key(cfg):
    _session_keys.pop(_key_id(cfg), None)
    if keyring:
        try:
            keyring.delete_password(KEYRING_SERVICE, _key_id(cfg))
        except Exception:
            pass


# ---------------------------------------------------------------- model picker
def _pick_model(cfg, key):
    try:
        models = list_models(cfg["provider"], cfg["base_url"], key)
    except APIError as e:
        print(f"Couldn't fetch the model list ({e}).")
        if "401" in str(e) or "403" in str(e) or "400" in str(e):
            print("That usually means the API key is wrong.")
        models = []
    if models:
        shown = models
        while True:
            print("\nAvailable models:")
            for i, m in enumerate(shown, 1):
                print(f"  {i:>3}) {m}")
            ans = input("Pick a number, or type words to filter the list: ").strip()
            if ans.isdigit() and 1 <= int(ans) <= len(shown):
                return shown[int(ans) - 1]
            if ans in models:
                return ans
            filtered = [m for m in models if all(w in m.lower() for w in ans.lower().split())]
            shown = filtered or models
            if not filtered:
                print("Nothing matched, showing all again.")
    while True:
        model = input("Type the exact model name (no spaces): ").strip()
        if model and not any(c in model for c in " *"):
            return model


def run_setup():
    print("\nWhich AI API do you want to use?")
    for k, p in PROVIDERS.items():
        print(f"  {k}) {p['label']}")
    choice = ""
    while choice not in PROVIDERS:
        choice = input("Choose 1-5: ").strip()
    p = PROVIDERS[choice]
    base_url = p["base_url"]
    if not base_url:
        base_url = input("Base URL (e.g. http://localhost:11434/v1 for Ollama): ").strip().rstrip("/")
    cfg = {"provider": p["name"], "base_url": base_url, "model": ""}

    forget_api_key(cfg)  # setup always asks for a fresh key
    key = _prompt_key(cfg, p["key_prefix"])
    _store_key(cfg, key)
    cfg["model"] = _pick_model(cfg, key)
    save_config(cfg)
    print(f"Using {cfg['model']}. Settings saved to {CONFIG_FILE}")
    return cfg
