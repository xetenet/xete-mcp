"""Every manifest in this repo describes the SAME package, or a directory shows the wrong one.

Three files now carry the package's identity, and each is read by a different channel:

  server.json           -> the official MCP registry, and PulseMCP ingests from there (verified
                           live: pulsemcp.com/servers/xete carries this description verbatim,
                           flagged official)
  gemini-extension.json -> Gemini CLI's gallery, discovered by CRAWL, no submission step
  pyproject.toml        -> PyPI, whose summary is rendered by several directories

Nothing keeps them in step. A version bump touching two of three is a listing that advertises a
release that does not exist, on a channel nobody remembers to check -- and Glama, mcp.so and
mcpservers.org re-crawl on their own schedule, so a wrong one can sit live for weeks.

This is cheap insurance against exactly the failure the registry just had: its record sat at
0.1.0 for two months, isLatest, pointing at an uninstallable build, because nothing compared it
to reality.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent


def _server_json():
    return json.loads((REPO / "server.json").read_text())


def _pyproject_version():
    m = re.search(r'^version\s*=\s*"([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M)
    assert m, "no version in pyproject.toml"
    return m.group(1)


def test_server_json_agrees_with_itself():
    """It carries the version TWICE -- top level and inside packages[]. The registry reads one,
    installers read the other."""
    d = _server_json()
    assert d["version"] == d["packages"][0]["version"], (
        f'server.json says {d["version"]} at top level and '
        f'{d["packages"][0]["version"]} in packages[0]')


def test_the_package_version_is_the_same_everywhere():
    d = _server_json()
    versions = {"server.json": d["version"], "pyproject.toml": _pyproject_version()}
    gem = REPO / "gemini-extension.json"
    if gem.exists():
        versions["gemini-extension.json"] = json.loads(gem.read_text())["version"]
    assert len(set(versions.values())) == 1, f"manifests disagree on version: {versions}"


def test_the_description_is_the_same_everywhere():
    """This string is syndicated VERBATIM. Two channels rendering two different sentences for
    one product is worse than either sentence being imperfect."""
    gem = REPO / "gemini-extension.json"
    if not gem.exists():
        pytest.skip("no gemini-extension.json")
    assert json.loads(gem.read_text())["description"] == _server_json()["description"]


@pytest.mark.parametrize("name", ["server.json", "glama.json", "gemini-extension.json"])
def test_no_manifest_carries_a_utf8_bom(name):
    """The MCP registry parser REJECTS a BOM outright -- this repo has already shipped one and
    had to strip it. Editors on Windows add them silently."""
    p = REPO / name
    if not p.exists():
        pytest.skip(f"{name} not present")
    assert p.read_bytes()[:3] != b"\xef\xbb\xbf", f"{name} starts with a UTF-8 BOM"


def test_glama_json_claims_a_real_github_user_not_the_org():
    """Glama matches `maintainers` against GitHub USER logins. `xetenet` is an Organization, so
    listing it silently fails to claim the listing -- and a claim that quietly does not apply is
    indistinguishable from one that does until you check the site."""
    p = REPO / "glama.json"
    if not p.exists():
        pytest.skip("no glama.json")
    d = json.loads(p.read_text())
    assert d.get("maintainers"), "glama.json has no maintainers; it claims nothing"
    assert "xetenet" not in d["maintainers"], (
        "glama.json lists the ORGANISATION as a maintainer. Glama matches user logins, so this "
        "claim will not apply.")
