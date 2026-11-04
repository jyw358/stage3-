"""Minimal OpenAI-compatible chat client (urllib, zero deps).

Works with DeepSeek (https://api.deepseek.com), GLM, qwen dashscope and any
OpenAI-compatible endpoint. Only what our worker loop needs: one-shot chat
with usage accounting.
"""
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0

    def add(self, u: dict) -> None:
        self.prompt_tokens += u.get("prompt_tokens", 0)
        self.completion_tokens += u.get("completion_tokens", 0)

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class OpenAICompatClient:
    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout_s: int = 300, max_retries: int = 4):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.usage = Usage()

    def chat(self, messages: list, temperature: float = 0.2,
             max_tokens: int = 4096) -> str:
        if "anthropic" in self.base_url:
            return self._chat_anthropic(messages, temperature, max_tokens)
        return self._chat_openai(messages, temperature, max_tokens)

    # ---- OpenAI shape (deepseek, glm v4 api, vllm, ...) ----
    def _chat_openai(self, messages: list, temperature: float,
                     max_tokens: int) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if "reasoner" in self.model.lower():
            # reasoner models: no temperature support; the chain-of-thought
            # shares the output budget. Measured on real construct prompts:
            # CoT alone reaches ~41k tokens -> 32k starves the final answer to
            # 0 bytes (finish=length); 64k lets CoT finish and the code block
            # survive (finish=stop). Billed on actual usage, so no idle cost.
            payload.pop("temperature", None)
            payload["max_tokens"] = max(max_tokens, 65536)
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        return self._request(req, lambda data: data["choices"][0]["message"]["content"] or "")

    # ---- Anthropic shape (GLM Coding Plan endpoint) ----
    def _chat_anthropic(self, messages: list, temperature: float,
                        max_tokens: int) -> str:
        system = "\n".join(m["content"] for m in messages
                           if m.get("role") == "system")
        rest = [m for m in messages if m.get("role") != "system"]
        payload = {
            "model": self.model,
            "max_tokens": max(max_tokens, 16384),
            "messages": rest,
        }
        if system:
            payload["system"] = system
        req = urllib.request.Request(
            f"{self.base_url}/v1/messages",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                # anthropic-compatible gateways accept either auth style;
                # send both so z.ai/bigmodel variants both work
                "x-api-key": self.api_key,
                "Authorization": f"Bearer {self.api_key}",
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )

        def extract(data):
            blocks = data.get("content") or []
            return "".join(b.get("text", "") for b in blocks
                           if b.get("type") == "text")

        return self._request(req, extract)

    # ---- shared retry loop ----
    def _request(self, req, extract):
        last_err = None
        for attempt in range(1, self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    data = json.loads(resp.read().decode())
                self.usage.calls += 1
                u = data.get("usage") or {}
                self.usage.prompt_tokens += u.get("prompt_tokens",
                                                  u.get("input_tokens", 0))
                self.usage.completion_tokens += u.get("completion_tokens",
                                                      u.get("output_tokens", 0))
                return extract(data)
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
                    json.JSONDecodeError, KeyError) as e:
                if isinstance(e, urllib.error.HTTPError):
                    try:
                        body = e.read().decode(errors="ignore")[:300]
                        e = RuntimeError(f"HTTP {e.code}: {body}")
                    except Exception:
                        pass
                    if "429" in str(e):
                        time.sleep(min(60 * attempt, 180))  # rate-limit backoff
                last_err = e
                if attempt == self.max_retries:
                    break
        raise RuntimeError(f"LLM call failed after {self.max_retries} tries: {last_err}")
