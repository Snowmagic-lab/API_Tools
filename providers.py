"""Provider adapters.

Each provider speaks a different JSON dialect for tool calling. These classes
hide that, so the agent loop only sees:

    provider.add_user(text)
    text, calls = provider.step()        # calls = [ToolCall(id, name, args), ...]
    provider.add_tool_results([(call, result_text), ...])

Each adapter keeps its own message history in its native format.
Only the standard library is used for HTTP, so there's nothing extra to install.
"""
import http.client
import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


class APIError(Exception):
    pass


def _post(url, headers, body, timeout=120):
    return _request(url, headers, json.dumps(body).encode("utf-8"), "POST", timeout)


def _get(url, headers, timeout=30):
    return _request(url, headers, None, "GET", timeout)


def _request(url, headers, data, method, timeout):
    req = urllib.request.Request(
        url, data=data, headers={"content-type": "application/json", **headers}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")[:800]
        except (OSError, http.client.HTTPException):
            detail = "(the error details couldn't be read)"
        raise APIError(f"HTTP {e.code} from {url}: {detail}") from None
    except urllib.error.URLError as e:
        raise APIError(f"Could not reach {url}: {e.reason}") from None
    except TimeoutError:
        raise APIError(f"{url} didn't respond within {timeout} seconds.") from None
    except (OSError, http.client.HTTPException) as e:
        raise APIError(f"The connection to {url} dropped: {type(e).__name__}") from None
    except ValueError:  # includes bad JSON and bad UTF-8
        raise APIError(f"{url} sent a reply that isn't valid JSON.") from None


class AnthropicProvider:
    """Anthropic Messages API (Claude models)."""

    def __init__(self, api_key, model, base_url, system_prompt, tools):
        self.url = base_url.rstrip("/") + "/v1/messages"
        self.headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
        self.model, self.system = model, system_prompt
        self.tools = [{"name": t["name"], "description": t["description"],
                       "input_schema": t["parameters"]} for t in tools]
        self.history = []

    def add_user(self, text):
        self.history.append({"role": "user", "content": text})

    def step(self):
        data = _post(self.url, self.headers, {
            "model": self.model, "max_tokens": 4096, "system": self.system,
            "tools": self.tools, "messages": self.history})
        content = data.get("content", [])
        self.history.append({"role": "assistant", "content": content})
        text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
        calls = [ToolCall(b["id"], b["name"], b.get("input") or {})
                 for b in content if b.get("type") == "tool_use"]
        return text, calls

    def add_tool_results(self, results):
        self.history.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": call.id, "content": result}
            for call, result in results]})


class OpenAICompatibleProvider:
    """OpenAI Chat Completions format — also used by Gemini's OpenAI endpoint,
    OpenRouter, Groq, Together, Ollama, LM Studio and many others."""

    def __init__(self, api_key, model, base_url, system_prompt, tools):
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.headers = {"authorization": f"Bearer {api_key}"}
        self.model = model
        self.tools = [{"type": "function", "function": {
            "name": t["name"], "description": t["description"],
            "parameters": t["parameters"]}} for t in tools]
        self.history = [{"role": "system", "content": system_prompt}]

    def add_user(self, text):
        self.history.append({"role": "user", "content": text})

    def step(self):
        data = _post(self.url, self.headers, {
            "model": self.model, "tools": self.tools, "messages": self.history})
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError):
            raise APIError(f"Unexpected response: {json.dumps(data)[:500]}")
        # Keep only the fields the API accepts back in history
        kept = {"role": "assistant", "content": msg.get("content") or ""}
        if msg.get("tool_calls"):
            kept["tool_calls"] = msg["tool_calls"]
        self.history.append(kept)
        calls = []
        for tc in msg.get("tool_calls") or []:
            raw = tc["function"].get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                args = {"_unparsed": raw}
            calls.append(ToolCall(tc["id"], tc["function"]["name"], args))
        return msg.get("content") or "", calls

    def add_tool_results(self, results):
        for call, result in results:
            self.history.append({"role": "tool", "tool_call_id": call.id, "content": result})


_NOT_CHAT = ("embed", "tts", "whisper", "dall-e", "image", "audio", "moderation",
             "transcribe", "realtime", "aqa", "imagen", "veo", "davinci", "babbage")


def list_models(provider, base_url, api_key):
    """Ask the API which models this key can use, so the user picks from a real list."""
    base = base_url.rstrip("/")
    if provider == "anthropic":
        data = _get(base + "/v1/models?limit=100",
                    {"x-api-key": api_key, "anthropic-version": "2023-06-01"})
    else:
        data = _get(base + "/models", {"authorization": f"Bearer {api_key}"})
    ids = []
    for m in data.get("data") or data.get("models") or []:
        mid = (m.get("id") or m.get("name") or "").removeprefix("models/")
        if mid and not any(w in mid.lower() for w in _NOT_CHAT):
            ids.append(mid)
    return sorted(set(ids))


def make_provider(cfg, api_key, system_prompt, tools):
    cls = AnthropicProvider if cfg["provider"] == "anthropic" else OpenAICompatibleProvider
    return cls(api_key, cfg["model"], cfg["base_url"], system_prompt, tools)
