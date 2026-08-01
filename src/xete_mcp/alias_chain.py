"""On-chain %alias resolution — THE source of truth for which wallet a %name points to.

WHY THIS EXISTS
---------------
A %alias is a name that money is sent to. If the only thing deciding which wallet
`%alex` means is an HTTP answer from the permit server, then that server — or anyone
who compromises it, or who sits on the network path to it — silently chooses the
destination of every payment addressed by name. The %name registry lives on Solana and
is readable by anyone, so there is no reason to take a server's word for it.

This module reads the registry directly: derive the name's PDA and do ONE
getAccountInfo (fast, and no getProgramAccounts, which public RPCs throttle). Ported
from the relay's alias_chain.py, which resolves the same way.

DIFFERENCE FROM THE RELAY'S COPY — read this before porting changes back.
The relay's resolve_owner() returns None on ANY failure, so "the RPC timed out" and
"nobody owns this name" are the same answer. That is acceptable for a display path and
unacceptable here, where the caller decides whether to release funds. `resolve_owner()`
below returns None ONLY for a name that is provably unclaimed (the RPC answered, and
the account does not exist), and raises AliasChainError for everything else. A caller
that cannot read the chain must fail, not fall back to a server's word.

WHAT IS CHECKED
---------------
  * the account is owned by the AXTREG registry program;
  * it is exactly the alias layout's length;
  * the name stored INSIDE the account is the name that was asked for, so a layout
    drift or an unexpected account at that address cannot return someone else's wallet.

The RPC endpoint itself is untrusted and gets the same treatment as the permit server
(https-or-loopback, no redirects, size-capped) — see safehttp.py. A hostile RPC can
still lie about the registry's contents; what it cannot do is do so over plain http
from a machine that is not this one.

CONFIGURATION (environment)
---------------------------
  XETE_SOLANA_RPC   Solana RPC used for %alias reads. Default
                    https://solana-rpc.publicnode.com — api.mainnet-beta throttles and
                    times out on reads, which for a resolver means a payment that
                    cannot be addressed. Same variable name the relay uses.
"""
from __future__ import annotations

import base64
import os

from solders.pubkey import Pubkey

from .safehttp import EndpointError, post_json, require_secure_url

AXTREG = Pubkey.from_string("AXTREGuYbpgcWFbZy124jcWDN2nd7mtmrCDsUojktZrd")

ENV_RPC = "XETE_SOLANA_RPC"
DEFAULT_RPC = "https://solana-rpc.publicnode.com"

# alias account layout (mirrors xete-alias): owner[0..32], name[32..64], name_len[64], len=106
A_OWNER, A_NAME, A_NAME_LEN, ALIAS_LEN = 0, 32, 64, 106
MAX_NAME_BYTES = 32                 # the name field is 32 bytes wide

RPC_TIMEOUT = 15
MAX_RPC_BYTES = 64 * 1024
COMMITMENT = "finalized"            # ownership decides where money goes; take the settled answer


class AliasChainError(RuntimeError):
    """The registry could not be read, or answered something unusable.

    NOT the same as "the name is unclaimed" — that is a None return. Anything that
    raises means the caller does not know who owns the name and must not guess.
    """


class InvalidAliasName(AliasChainError):
    """The string cannot be a %name, so no lookup was attempted."""


def rpc_url() -> str:
    """The RPC endpoint for alias reads, checked before it is used."""
    return require_secure_url(os.environ.get(ENV_RPC) or DEFAULT_RPC, ENV_RPC)


def normalize_name(name: str) -> str:
    """The canonical registry form of a %name: no leading %, no surrounding space, lower case.

    Lower case is not cosmetic. The registry PDA is derived from the exact bytes of the
    name, and the permit server lower-cases before it looks anything up, so %Alice and
    %alice are the SAME name to the server and DIFFERENT addresses on chain. Without
    this, a name claimed as `alice` would resolve as unclaimed when written `%Alice`.
    """
    if not isinstance(name, str):
        raise InvalidAliasName(f"a %name must be text, got {type(name).__name__}.")
    bare = name.strip().lstrip("%").strip().lower()
    if not bare:
        raise InvalidAliasName("an empty string is not a %name.")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in bare):
        raise InvalidAliasName(
            f"{name!r} contains whitespace or control characters, which no %name can.")
    encoded = bare.encode("utf-8")
    if len(encoded) > MAX_NAME_BYTES:
        raise InvalidAliasName(
            f"%{bare} is {len(encoded)} bytes; the registry stores at most {MAX_NAME_BYTES}.")
    return bare


def alias_pda(name: str) -> Pubkey:
    """The registry account address for a name. Pure — no I/O."""
    return Pubkey.find_program_address([b"alias", normalize_name(name).encode()], AXTREG)[0]


def resolve_owner(name: str, rpc: str | None = None) -> str | None:
    """The base58 owner wallet of %name, read from the chain.

    Returns None ONLY when the RPC answered and the registry account does not exist,
    i.e. the name is provably unclaimed. Raises AliasChainError when the answer could
    not be obtained or could not be trusted — never conflate the two.
    """
    bare = normalize_name(name)
    pda = alias_pda(bare)
    url = rpc_url() if rpc is None else require_secure_url(rpc, ENV_RPC)

    try:
        body = post_json(
            url,
            {"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
             "params": [str(pda), {"encoding": "base64", "commitment": COMMITMENT}]},
            timeout=RPC_TIMEOUT,
            max_bytes=MAX_RPC_BYTES,
        )
    except EndpointError as e:
        raise AliasChainError(
            f"the %alias registry could not be read from {url}: {e} Refusing to guess an owner "
            f"for %{bare} — no server's word is used as a substitute."
        ) from e

    # A JSON-RPC error arrives as HTTP 200 with an "error" member. Reading only "result"
    # would turn every RPC failure into "this name is unclaimed".
    if "error" in body:
        err = body.get("error")
        detail = err.get("message") if isinstance(err, dict) else err
        raise AliasChainError(
            f"{url} returned a JSON-RPC error resolving %{bare}: {str(detail)[:200]}")

    result = body.get("result")
    if not isinstance(result, dict) or "value" not in result:
        raise AliasChainError(
            f"{url} returned a getAccountInfo response with no result value for %{bare}.")

    value = result["value"]
    if value is None:
        return None                                   # provably unclaimed
    if not isinstance(value, dict):
        raise AliasChainError(f"{url} returned a non-object account for %{bare}.")

    owner_program = value.get("owner")
    if owner_program != str(AXTREG):
        raise AliasChainError(
            f"the account at {pda} is owned by program {str(owner_program)[:60]!r}, not the xete "
            f"alias registry {AXTREG}. Not treating it as a %{bare} registration.")

    raw_data = value.get("data")
    if (not isinstance(raw_data, list) or len(raw_data) != 2
            or not isinstance(raw_data[0], str) or raw_data[1] != "base64"):
        raise AliasChainError(f"{url} returned account data for %{bare} in an unexpected form.")
    try:
        data = base64.b64decode(raw_data[0], validate=True)
    except Exception:
        raise AliasChainError(f"{url} returned account data for %{bare} that is not base64.") from None
    if len(data) != ALIAS_LEN:
        raise AliasChainError(
            f"the registry account for %{bare} is {len(data)} bytes, not the {ALIAS_LEN} byte "
            "alias layout. Not reading an owner out of it.")

    # The name stored in the account must be the name we asked for. A mismatch means the
    # layout changed or that address is not what we think it is; either way, returning
    # the wallet in the first 32 bytes would be returning a stranger's address.
    stored_len = data[A_NAME_LEN]
    if stored_len > MAX_NAME_BYTES:
        raise AliasChainError(
            f"the registry account for %{bare} declares a {stored_len} byte name, over the "
            f"{MAX_NAME_BYTES} byte field.")
    stored = data[A_NAME:A_NAME + stored_len]
    if stored != bare.encode("utf-8"):
        raise AliasChainError(
            f"the registry account at {pda} holds the name {stored!r}, not {bare!r}. Refusing to "
            "return its owner.")

    return str(Pubkey.from_bytes(bytes(data[A_OWNER:A_OWNER + 32])))
