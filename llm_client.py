"""llm_client.py — one chat entry point for every local-model caller in xete-mcp.

WHY THIS EXISTS. Every consumer here (`rag_chat`, `knowledge_mcp_server`, `rag_ultracode`,
`brainstorm_engine`) hand-rolled the same POST to Ollama's `/api/chat`. That was fine while
`llama3.1:8b` was the only local model. It stopped being fine on 2026-08-15, when the
qwen3.6-35B-A3B MoE measured **7.6x faster end-to-end through llama.cpp than through Ollama**
on an identical RAG question (1148s -> 150s) — a gap that comes entirely from two flags Ollama
does not expose (`-ub 2048`, `--n-cpu-moe 32`). Getting that speedup means talking to
`llama-server`, which speaks OpenAI's `/v1/chat/completions`, not Ollama's `/api/chat`.

Rather than fork every caller, this module presents ONE interface in Ollama's shape (the shape
they already use) and translates on the way out. Switching backend is an env var, not an edit:

    XETE_LLM_BACKEND=ollama    (default — unchanged behaviour, llama3.1:8b)
    XETE_LLM_BACKEND=llamacpp  (llama-server on :8080)

EMBEDDINGS STAY ON OLLAMA, BUT OFF THE GPU. `embed()` still calls Ollama's /api/embeddings —
the index was built with `nomic-embed-text` and re-embedding against a different model would
invalidate it — but pins the request to CPU (`num_gpu: 0`). A query embeds immediately before
the chat call, so without that pin Ollama parks the embed model in VRAM beside llama-server
and prefill drops by roughly an order of magnitude. Measured cost of the pin: 30ms vs 28ms.
Bulk ingest is a separate concern and is deliberately left on the GPU.

Some callers named above are local-only dev tooling and are not part of this repository; the
module is useful standalone and has no dependency on them.

Stdlib only (urllib/json/os), matching the existing house style in this directory.
"""
from __future__ import annotations

import json
import os
import urllib.request

import sys

_EXPLICIT = os.environ.get("XETE_LLM_BACKEND", "").strip().lower()
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
LLAMACPP_URL = os.environ.get("LLAMACPP_URL", "http://127.0.0.1:8080").rstrip("/")
CHAT_MODEL = os.environ.get("CHAT_MODEL", "llama3.1:8b")
DEFAULT_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "600"))

# llama.cpp ignores per-request context (it is fixed by `-c` at server launch), so `num_ctx`
# is accepted and dropped on that path rather than silently pretending to have applied.
# Sampling defaults below match qwen3.6's baked-in Ollama params so a backend swap does not
# also become an unannounced sampling change.
LLAMACPP_SAMPLING = {
    "temperature": float(os.environ.get("LLM_TEMPERATURE", "1.0")),
    "top_p": float(os.environ.get("LLM_TOP_P", "0.95")),
    "top_k": int(os.environ.get("LLM_TOP_K", "20")),
    "presence_penalty": float(os.environ.get("LLM_PRESENCE_PENALTY", "1.5")),
    "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", "4096")),
}


def _probe(url):
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _resolve_backend():
    """Explicit env = strict (never silently substitutes). Unset = prefer llama.cpp, fall
    back to Ollama with a LOUD warning.

    The two halves matter for different reasons. Strict-when-explicit means a benchmark or a
    test that asks for a backend gets that backend or an error — never a quiet substitution
    that would make its numbers a lie. Graceful-when-unset means the MCP server (spawned with
    no env at all) still answers when `qwen-server` happens to be stopped, instead of every
    knowledge_ask failing because a 22GB service is not running.
    """
    if _EXPLICIT:
        return _EXPLICIT
    if _probe(LLAMACPP_URL + "/health"):
        return "llamacpp"
    print("[llm_client] llama-server not reachable at %s - falling back to ollama/%s. "
          "Start it with: sudo systemctl start qwen-server"
          % (LLAMACPP_URL, CHAT_MODEL), file=sys.stderr)
    return "ollama"


BACKEND = _resolve_backend()


def backend_name() -> str:
    return BACKEND


def describe() -> str:
    """One line for logs/banners so a caller can always show which brain it is using."""
    if BACKEND == "llamacpp":
        return f"llama.cpp @ {LLAMACPP_URL}"
    return f"ollama {CHAT_MODEL} @ {OLLAMA_URL}"


def health() -> bool:
    """True if the configured backend answers. Callers use this to fail loudly at startup."""
    url = LLAMACPP_URL + "/health" if BACKEND == "llamacpp" else OLLAMA_URL + "/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _post(url: str, payload: dict, timeout: int):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    return urllib.request.urlopen(req, timeout=timeout)


def _chat_ollama(messages, num_ctx, stream, on_token, timeout):
    payload = {"model": CHAT_MODEL, "messages": messages, "stream": bool(stream)}
    if num_ctx:
        payload["options"] = {"num_ctx": num_ctx}
    with _post(OLLAMA_URL + "/api/chat", payload, timeout) as r:
        if not stream:
            return json.loads(r.read())["message"]["content"]
        full = ""
        for line in r:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            piece = obj.get("message", {}).get("content", "")
            if piece:
                full += piece
                if on_token:
                    on_token(piece)
            if obj.get("done"):
                break
        return full


def _chat_llamacpp(messages, num_ctx, stream, on_token, timeout, think):
    # num_ctx intentionally unused — see module docstring.
    payload = {"messages": messages, "stream": bool(stream)}
    payload.update(LLAMACPP_SAMPLING)
    if not think:
        # MEASURED 2026-08-15: qwen3.6 spends its budget reasoning even on trivial prompts —
        # "Reply with exactly: PONG" cost 172 tokens / 10.9s with thinking on and 3 tokens /
        # 0.1s with it off. That is ~100x on short synthesis work, which is most of what the
        # RAG callers do. NOTE `reasoning_budget: 0` does NOT suppress it (tested: still 138
        # tokens); only the template kwarg does.
        payload["chat_template_kwargs"] = {"enable_thinking": False}
    with _post(LLAMACPP_URL + "/v1/chat/completions", payload, timeout) as r:
        if not stream:
            d = json.loads(r.read())
            msg = d["choices"][0].get("message") or {}
            # qwen3.6 is a thinking model: llama.cpp puts the reasoning trace in
            # `reasoning_content` and leaves `content` empty if the token budget runs out
            # mid-thought. Returning "" silently is how that failure hides, so surface it.
            content = msg.get("content") or ""
            if not content and (msg.get("reasoning_content") or ""):
                raise RuntimeError(
                    "model produced only reasoning and no answer "
                    "(raise LLM_MAX_TOKENS, currently %s)" % LLAMACPP_SAMPLING["max_tokens"]
                )
            return content
        full = ""
        for raw in r:
            raw = raw.strip()
            if not raw or not raw.startswith(b"data:"):
                continue
            data = raw[5:].strip()
            if data == b"[DONE]":
                break
            try:
                obj = json.loads(data)
            except ValueError:
                continue
            delta = (obj.get("choices") or [{}])[0].get("delta") or {}
            piece = delta.get("content") or ""
            if piece:
                full += piece
                if on_token:
                    on_token(piece)
        return full


def _to_openai_messages(messages):
    """Re-serialize any Ollama-shaped tool_calls before sending to llama.cpp.

    Callers hold conversation history in Ollama's shape, where `function.arguments` is a
    dict. OpenAI wants it as a JSON *string*. An assistant turn that requested tools gets
    appended back into the history and re-sent on the next step, so this has to run on the
    way OUT as well as parsing on the way IN — otherwise the second tool step sends a dict
    where a string is expected and the model silently loses the call it just made.
    """
    out = []
    for m in messages:
        tcs = m.get("tool_calls") if isinstance(m, dict) else None
        if not tcs:
            out.append(m)
            continue
        fixed = []
        for tc in tcs:
            fn = dict(tc.get("function") or {})
            if isinstance(fn.get("arguments"), (dict, list)):
                fn["arguments"] = json.dumps(fn["arguments"])
            fixed.append({**tc, "function": fn})
        out.append({**m, "tool_calls": fixed})
    return out


def _to_ollama_message(msg):
    """Parse OpenAI `function.arguments` (a JSON string) back into the dict callers expect."""
    tcs = msg.get("tool_calls")
    if not tcs:
        return msg
    fixed = []
    for tc in tcs:
        fn = dict(tc.get("function") or {})
        if isinstance(fn.get("arguments"), str):
            try:
                fn["arguments"] = json.loads(fn["arguments"])
            except ValueError:
                # Leave it as a string rather than guess — a caller doing .get() on it will
                # fail loudly, which beats silently passing a malformed tool call through.
                pass
        fixed.append({**tc, "function": fn})
    return {**msg, "tool_calls": fixed}


def chat_message(messages, tools=None, num_ctx=None, timeout=None, think=None):
    """Like chat(), but returns the whole assistant MESSAGE dict in Ollama shape.

    Needed by tool-calling callers, which inspect `message.tool_calls` and append the
    assistant turn back into history. Tool schemas pass through unchanged in both backends.
    """
    timeout = timeout or DEFAULT_TIMEOUT
    if think is None:
        think = os.environ.get("LLM_THINK", "0").strip().lower() in ("1", "true", "yes", "on")

    if BACKEND == "ollama":
        payload = {"model": CHAT_MODEL, "messages": messages, "stream": False}
        if tools:
            payload["tools"] = tools
        if num_ctx:
            payload["options"] = {"num_ctx": num_ctx}
        with _post(OLLAMA_URL + "/api/chat", payload, timeout) as r:
            return json.loads(r.read()).get("message", {}) or {}

    payload = {"messages": _to_openai_messages(messages), "stream": False}
    payload.update(LLAMACPP_SAMPLING)
    if tools:
        payload["tools"] = tools
    if not think:
        payload["chat_template_kwargs"] = {"enable_thinking": False}
    with _post(LLAMACPP_URL + "/v1/chat/completions", payload, timeout) as r:
        d = json.load(r)
    return _to_ollama_message(d["choices"][0].get("message") or {})


def embed(text, model, timeout=120):
    """Embed `text` with an Ollama model, pinned to CPU.

    Embeddings stay on Ollama (the RAG store was built with nomic-embed-text; re-embedding
    20k chunks against anything else would invalidate it) — but they must NOT touch the GPU.
    Measured 2026-08-15: a knowledge_ask embeds the query immediately before the chat call,
    which made Ollama load nomic-embed-text onto the same card as llama-server and dropped
    qwen's prefill from ~400 t/s to 45 t/s for that request. `num_gpu: 0` keeps the embed
    model on CPU, where a 274MB model costs milliseconds, and leaves the GPU to qwen alone.
    Ollama's keep_alive would otherwise hold that VRAM for minutes after the call.
    """
    body = json.dumps({"model": model, "prompt": text, "options": {"num_gpu": 0}}).encode()
    req = urllib.request.Request(
        OLLAMA_URL + "/api/embeddings", data=body,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["embedding"]


def chat(messages, num_ctx=None, stream=False, on_token=None, timeout=None, think=None):
    """Send `messages` to the configured backend and return the assistant text.

    messages  — Ollama/OpenAI-shaped [{"role":..., "content":...}]
    num_ctx   — honoured on Ollama; ignored on llama.cpp (fixed by `-c` at launch)
    stream    — if True, `on_token(piece)` is called per chunk as it arrives
    think     — llama.cpp only. None = env default (LLM_THINK, off unless set). Reasoning is
                OFF by default because it costs ~100x on short prompts for no gain on
                extraction/synthesis; turn it ON for genuinely hard work (code-gen, critique),
                where it is worth the wall-clock.
    """
    timeout = timeout or DEFAULT_TIMEOUT
    if think is None:
        think = os.environ.get("LLM_THINK", "0").strip().lower() in ("1", "true", "yes", "on")
    if BACKEND == "llamacpp":
        return _chat_llamacpp(messages, num_ctx, stream, on_token, timeout, think)
    if BACKEND != "ollama":
        raise ValueError(
            "XETE_LLM_BACKEND must be 'ollama' or 'llamacpp', got %r" % BACKEND
        )
    return _chat_ollama(messages, num_ctx, stream, on_token, timeout)
