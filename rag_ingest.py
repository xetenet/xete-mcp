#!/usr/bin/env python3
"""rag_ingest.py — build a local vector index over every xete .md doc on this machine.

Sovereign + dependency-light: stdlib + requests only (no numpy, no Chroma, no cloud).
Embeds each doc chunk with a local Ollama embedding model and saves vectors to a pickle.
Query it with rag_query.py.

  python3 rag_ingest.py                 # full re-index
  EMBED_MODEL=nomic-embed-text python3 rag_ingest.py
"""
import os, re, sys, time, pickle, math, json, subprocess, urllib.request

ROOT = os.environ.get("RAG_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STORE = os.environ.get("RAG_STORE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "rag_store.pkl"))
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")

# Index docs whose path contains 'xete'. Memory (.claude) is included by default now
# (RAG_INCLUDE_MEMORY=0 to exclude). A few memory files point at secrets/credentials —
# never index those, even with memory on.
INCLUDE_MEMORY = os.environ.get("RAG_INCLUDE_MEMORY", "1") != "0"
# Qualify a doc if its path matches any ecosystem hint: xete itself, sibling projects
# (House Elf desktop + Saga mobile), and the curated knowledge base under xete-mcp/knowledge.
INCLUDE_HINTS = ("xete", "house-elf", "saga", "/knowledge/")
SKIP_SUBSTR = ("backup", "archive", "-locked", "refactor-rebase",
               "sample-apps", "solana-mobile-docs", "/node_modules/",
               "/legal/", "jdk-", "/.venv/", "/venv/")  # bundled JDK/venv license text isn't knowledge
SENSITIVE = {"xete-deploy-keypair-location.md", "xete-account-logins.md",
             "tet-vanity-results-doc.md"}   # plus any sec-*.md (handled below)

CHUNK = 1100          # ~chars per chunk
OVERLAP = 150         # char overlap between chunks


def discover():
    # os.walk over the WSL 9p /mnt/c mount is pathologically slow; shell out to find,
    # pruning the heavy dirs (esp. AppData) and capping depth.
    prune = (r"\( -type d \( -name node_modules -o -name .git -o -name .venv -o -name dist "
             r"-o -name build -o -name target -o -name site-packages -o -name __pycache__ "
             r"-o -iname AppData \) -prune \)")
    cmd = f"find {ROOT} -maxdepth 6 {prune} -o -type f -name '*.md' -print"
    out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=180).stdout
    files = []
    for line in out.splitlines():
        low = line.lower()
        if not any(h in low for h in INCLUDE_HINTS) or any(s in low for s in SKIP_SUBSTR):
            continue
        base = os.path.basename(line)
        if base in SENSITIVE or base.startswith("sec-"):
            continue
        if not INCLUDE_MEMORY and "/.claude/" in line:
            continue
        files.append(line)
    return sorted(set(files))


def chunk_text(text):
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) <= CHUNK:
        return [text] if text else []
    chunks, i = [], 0
    while i < len(text):
        end = min(i + CHUNK, len(text))
        # try to break on a paragraph/line boundary near the end
        nl = text.rfind("\n", i + CHUNK - 250, end)
        if nl > i:
            end = nl
        piece = text[i:end].strip()
        if piece:
            chunks.append(piece)
        if end >= len(text):
            break
        i = max(end - OVERLAP, i + 1)
    return chunks


def embed(text):
    body = json.dumps({"model": EMBED_MODEL, "prompt": text}).encode()
    req = urllib.request.Request(OLLAMA + "/api/embeddings", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["embedding"]


def norm(v):
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def main():
    files = discover()
    print(f"discovered {len(files)} xete .md docs under {ROOT}")
    records, t0, n_chunks = [], time.time(), 0
    for fi, path in enumerate(files, 1):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception as e:
            print(f"  skip {path}: {e}"); continue
        chunks = chunk_text(text)
        rel = path.replace(ROOT + "/", "")
        for ci, ch in enumerate(chunks):
            try:
                vec = norm(embed(ch))
            except Exception as e:
                print(f"  embed fail {rel}#{ci}: {e}"); continue
            records.append({"path": rel, "abspath": path, "chunk": ci, "text": ch, "vec": vec})
            n_chunks += 1
        if fi % 10 == 0 or fi == len(files):
            dt = time.time() - t0
            print(f"  [{fi}/{len(files)}] {n_chunks} chunks  ({dt:.0f}s, {n_chunks/max(dt,1):.1f} chunks/s)")
    with open(STORE, "wb") as f:
        pickle.dump({"model": EMBED_MODEL, "dim": len(records[0]["vec"]) if records else 0,
                     "built": int(time.time()), "records": records}, f)
    print(f"\nDONE: {n_chunks} chunks from {len(files)} docs -> {STORE} "
          f"({os.path.getsize(STORE)//1024} KB, {time.time()-t0:.0f}s)")


if __name__ == "__main__":
    main()
