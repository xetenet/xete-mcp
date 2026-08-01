"""Hardened HTTP for services this client does NOT trust.

Everything this package talks to over the network is a service that could be hostile:
the %alias permit server (a separate service, repointable with XETE_PERMIT_URL) and a
public Solana RPC endpoint. Neither authenticates itself to us. A plain
`requests.get(...).json()` hands such a service four separate ways to steer this client:

  * plain http:// — anyone on the path rewrites the answer;
  * a redirect — the service silently sends the request, and the data we act on,
    somewhere else entirely;
  * an error page — `.json()` on a 500 or an empty 404 body raises a decoder error, and
    the caller reports a confusing parse failure instead of "that server said no";
  * an unbounded body — parsed into memory before anyone looks at its size.

Every helper here closes one of those. What it deliberately does NOT do is make the
answer TRUE: a well-formed 200 from a hostile server is still a hostile server's word.
Callers must label anything sourced this way as unverified, and must not decide where
money goes on it — see alias_chain.py for the chain-backed alternative.

Fields are pulled out of a response with `project()` against an explicit allow-list
rather than by handing the server's object through, so a server cannot inject keys into
data an agent reads as if this client had produced them.
"""
from __future__ import annotations

import ipaddress
import json
from urllib.parse import urlsplit

import requests

DEFAULT_TIMEOUT = 15
MAX_RESPONSE_BYTES = 64 * 1024      # generous for a JSON answer, tiny for an attack
_CHUNK = 8192
_MAX_IGNORED_REPORTED = 20


class EndpointError(RuntimeError):
    """A request to an untrusted endpoint did not produce a usable answer.

    `kind` is a stable slug a tool can turn into a clean, specific message rather than
    leaking a stringified decoder exception. `status` is the HTTP status when there was
    one.
    """

    def __init__(self, message: str, *, kind: str = "endpoint_error",
                 status: int | None = None, url: str | None = None):
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.url = url


class InsecureEndpoint(EndpointError):
    """The URL itself was refused, before any request was made. Nothing left the machine."""

    def __init__(self, message: str, *, url: str | None = None):
        super().__init__(message, kind="insecure_endpoint", url=url)


# ── URL admission ────────────────────────────────────────────────────────────────────

def is_loopback(host: str) -> bool:
    """True only for the local machine. `localhost.evil.com` is not loopback."""
    h = (host or "").strip().lower().rstrip(".")
    if h in ("localhost", "ip6-localhost", "ip6-loopback"):
        return True
    if h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def require_secure_url(url: str, env_name: str) -> str:
    """Return `url` if it is safe to send a request to, else raise InsecureEndpoint.

    https is required. Plain http is permitted ONLY for a loopback host, which is the
    real case (a local test validator, a permit server on 127.0.0.1) and is not
    interceptable by a third party. Credentials embedded in the URL are refused: they
    would be sent to whatever host the URL names, and a mistyped host is then a
    disclosed secret.
    """
    raw = (url or "").strip()
    if not raw:
        raise InsecureEndpoint(
            f"{env_name} is empty. Set it to the https:// URL of the service to use.")
    try:
        parsed = urlsplit(raw)
    except ValueError as e:
        raise InsecureEndpoint(f"{env_name} = {raw!r} is not a URL ({e}).", url=raw) from None

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https", "http"):
        raise InsecureEndpoint(
            f"{env_name} = {raw!r} uses the {scheme or 'missing'!r} scheme. Only https:// is "
            "accepted (http:// only for a loopback address). Nothing was requested.", url=raw)
    if parsed.username or parsed.password:
        raise InsecureEndpoint(
            f"{env_name} = {raw!r} embeds credentials in the URL. They would be sent to whatever "
            "host that URL names; put them in a header, not the URL. Nothing was requested.",
            url=raw)

    host = parsed.hostname
    if not host:
        raise InsecureEndpoint(
            f"{env_name} = {raw!r} names no host. Nothing was requested.", url=raw)
    if scheme == "http" and not is_loopback(host):
        raise InsecureEndpoint(
            f"{env_name} = {raw!r} is plain http:// to {host!r}. Anyone on the network path can "
            "read and rewrite that answer, and these tools use the answer to decide where money "
            "goes. Use https://, or a loopback address (localhost / 127.0.0.1) for local "
            "testing. Nothing was requested.", url=raw)
    return raw


# ── requests ─────────────────────────────────────────────────────────────────────────

def get_json(url: str, params: dict | None = None, *, timeout: float = DEFAULT_TIMEOUT,
             max_bytes: int = MAX_RESPONSE_BYTES) -> dict:
    """GET a JSON object, or raise EndpointError. Never follows a redirect."""
    return _request("GET", url, params=params, timeout=timeout, max_bytes=max_bytes)


def post_json(url: str, payload: dict, *, timeout: float = DEFAULT_TIMEOUT,
              max_bytes: int = MAX_RESPONSE_BYTES) -> dict:
    """POST JSON and read back a JSON object, or raise EndpointError. Never follows a redirect."""
    return _request("POST", url, json_body=payload, timeout=timeout, max_bytes=max_bytes)


def _request(method: str, url: str, *, params=None, json_body=None,
             timeout: float, max_bytes: int) -> dict:
    kwargs = {
        "timeout": timeout,
        "allow_redirects": False,   # a service that can redirect us can relocate the decision
        "stream": True,             # so the body can be capped BEFORE it is parsed
        "headers": {"Accept": "application/json"},
    }
    if params is not None:
        kwargs["params"] = params
    if json_body is not None:
        kwargs["json"] = json_body
    try:
        resp = requests.request(method, url, **kwargs)
    except requests.RequestException as e:
        raise EndpointError(
            f"{url} could not be reached ({e.__class__.__name__}: {str(e)[:200]}).",
            kind="unreachable", url=url) from e
    return _read_json(resp, url, max_bytes)


def _read_json(resp, url: str, max_bytes: int) -> dict:
    with resp:
        status = resp.status_code
        location = resp.headers.get("Location")
        # raise_for_status() treats 3xx as success. With redirects disabled a 3xx is an
        # answer we refuse, so it has to be caught explicitly and first.
        if 300 <= status < 400:
            raise EndpointError(
                f"{url} answered {status} redirecting to {str(location)[:200]!r}. Redirects are "
                "not followed: a service that can redirect this client can move where its answer "
                "comes from, and these answers decide where money goes.",
                kind="redirect_refused", status=status, url=url)
        if status in (404, 405, 410, 501):
            raise EndpointError(
                f"{url} answered {status}: this server does not provide that endpoint.",
                kind="endpoint_not_available", status=status, url=url)
        try:
            resp.raise_for_status()
        except requests.HTTPError as e:
            raise EndpointError(
                f"{url} answered {status} ({str(e)[:200]}).",
                kind="http_error", status=status, url=url) from e

        declared = (resp.headers.get("Content-Length") or "").strip()
        if declared.isdigit() and int(declared) > max_bytes:
            raise EndpointError(
                f"{url} declared a {int(declared)} byte body, over the {max_bytes} byte cap. "
                "It was not read or parsed.",
                kind="response_too_large", status=status, url=url)

        chunks, total = [], 0
        try:
            for chunk in resp.iter_content(_CHUNK):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise EndpointError(
                        f"{url} sent more than the {max_bytes} byte cap. The connection was "
                        "dropped and nothing was parsed.",
                        kind="response_too_large", status=status, url=url)
                chunks.append(chunk)
        except requests.RequestException as e:
            raise EndpointError(
                f"{url} failed mid-body ({e.__class__.__name__}: {str(e)[:200]}).",
                kind="unreachable", status=status, url=url) from e

    body = b"".join(chunks)
    if not body.strip():
        raise EndpointError(
            f"{url} answered {status} with an empty body where JSON was expected.",
            kind="empty_response", status=status, url=url)
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as e:
        raise EndpointError(
            f"{url} answered {status} with {len(body)} bytes that are not JSON "
            f"({e.__class__.__name__}).",
            kind="bad_json", status=status, url=url) from None
    if not isinstance(data, dict):
        raise EndpointError(
            f"{url} answered {status} with a JSON {type(data).__name__}, not an object.",
            kind="bad_json", status=status, url=url)
    return data


# ── allow-listed field extraction ────────────────────────────────────────────────────

def as_int(value):
    """An integer, or None. Booleans are not integers here."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def as_bool(value):
    return value if isinstance(value, bool) else None


def as_str(value, limit: int = 200):
    if not isinstance(value, str):
        return None
    return value[:limit]


def project(data: dict, spec: dict) -> dict:
    """Copy ONLY the allow-listed keys out of an untrusted object, each through a coercer.

    Keys absent from `spec` never reach the caller, so a server cannot add fields to
    something an agent will read as this client's own output. Their NAMES are reported
    under `fields_ignored` — dropping data silently is how a protocol change becomes an
    unexplained outage.
    """
    out = {}
    for key, coerce in spec.items():
        if key in data:
            out[key] = coerce(data[key])
    extra = sorted(str(k)[:64] for k in data.keys() if k not in spec)
    if extra:
        out["fields_ignored"] = extra[:_MAX_IGNORED_REPORTED]
    return out
