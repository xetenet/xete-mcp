#!/usr/bin/env python3
"""brainstorm_engine.py — combinatorial idea generator over the xete RAG index.

Not a Q&A tool. This deliberately pairs DISTANT, dissimilar material from across your
project (or pairs a topic you name against something unexpected elsewhere in the corpus),
asks the local model to find a genuine structural connection through several different
lenses, self-critiques its own output to kill generic filler, and appends only the
survivors to a running insights log you can skim later.

Fully local/sovereign: same embedding model + chat model as rag_chat.py, no cloud calls.

  python3 brainstorm_engine.py                          # one round, fully random pairing
  python3 brainstorm_engine.py --rounds 10               # 10 rounds back to back
  python3 brainstorm_engine.py --seed "royalty protocol" # anchor one side on a topic you name
  python3 brainstorm_engine.py --loop 120                # run continuously for 120 minutes
  python3 brainstorm_engine.py --log insights.md          # custom log path (default below)
  python3 brainstorm_engine.py --seed "non-custodial design" --pair-with tech-geopolitics
    # anchor A on a topic, force anchor B to come from a specific corpus area (path substring) -
    # for deliberately colliding two known-fertile areas instead of hoping random pairing finds one

Design notes (why it's built this way):
  - Retrieval finds SIMILAR chunks by design; genuine cross-domain insight needs the
    opposite — this deliberately searches for the LEAST similar chunk to pair against,
    not the most similar, to force real juxtaposition rather than restating one topic.
  - Each pairing is examined through several distinct lenses in separate model calls
    (not one blended prompt) because a single framing reliably converges on the same
    shallow, obvious angle — forcing different angles is what surfaces non-obvious ones.
  - A self-critique pass follows: the model is shown its own candidate connections and
    asked which (if any) survive scrutiny as genuinely non-obvious, grounded, and
    useful. Most candidates are expected to be discarded — that's the filter working,
    not a bug. Only survivors get logged.
"""
import os, sys, json, pickle, math, random, time, argparse, urllib.request
from datetime import datetime, timezone

STORE = os.environ.get("RAG_STORE", "/mnt/c/Users/jshed/xete-mcp/rag_store.pkl")
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
CHAT_MODEL = os.environ.get("CHAT_MODEL", "llama3.1:8b")
NUM_CTX = int(os.environ.get("NUM_CTX", "8192"))
DEFAULT_LOG = os.environ.get("BRAINSTORM_LOG", "/mnt/c/Users/jshed/xete-mcp/brainstorm_insights.md")

LENSES = [
    ("mechanism", "What underlying MECHANISM, process, or structural pattern do these two things "
                   "actually share — not a surface theme, the actual moving parts?"),
    ("values", "What PRINCIPLE, tradeoff, or value judgment shows up in both of these, even though "
               "they're from completely different areas?"),
    ("failure", "Is there a FAILURE MODE, risk, or mistake that both of these are vulnerable to in "
                "the same underlying way, even if it hasn't happened in both yet?"),
    ("opportunity", "Does putting these two things side by side suggest an UNBUILT IDEA — something "
                     "that isn't in either piece of context alone, but falls out of combining them?"),
]

CONNECTION_SYSTEM = """You are a combinatorial-creativity engine over John's personal xete project \
knowledge base — sovereign, local, offline. You will be shown two DELIBERATELY UNRELATED pieces of \
context pulled from different, distant parts of the project, plus a specific lens to view them \
through. Your job is to find a genuine, structural connection through that lens — not a vague \
thematic one ("they're both about trust"). If you genuinely cannot find a real connection through \
this lens, say so plainly in one line rather than inventing a strained one — a discarded attempt \
costs nothing, a fake connection wastes a human's time reading it. Ground anything you claim in \
the actual context shown; do not invent details neither chunk supports. Be concise: 3-5 sentences \
for a real connection, one line if there isn't one."""

CRITIQUE_SYSTEM = """You are the skeptical filter in a combinatorial-creativity pipeline. You will be \
shown several candidate "connections" the same local model just generated between two unrelated \
pieces of context, each through a different lens. Most candidates from an 8B local model are \
generic, obvious, or a stretch — your job is to say so bluntly. Pick AT MOST ONE candidate that is \
genuinely non-obvious, grounded in what the candidate text ITSELF claims (not what you wish it \
claimed), and would be worth a human's time to read. If a candidate hedges or denies finding a real \
connection, your reason must reflect that hedge honestly — do not describe a candidate as \
"structurally grounded" if its own text said otherwise; either it stands on its own merits as \
stated, or it doesn't survive. If none clear that bar, say NONE and explain why in one line. Do not \
soften your standard to make something survive — a log with fewer, better entries is more useful \
than one padded with filler. Respond in this exact format:
VERDICT: <lens-name-of-survivor, or NONE>
REASON: <one line, honest about what the surviving candidate actually claims>
"""


def embed(text):
    body = json.dumps({"model": _embed_model, "prompt": text}).encode()
    req = urllib.request.Request(OLLAMA + "/api/embeddings", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["embedding"]


def norm(v):
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def cosine(a, b):
    return sum(x * y for x, y in zip(a, b))


def chat(system, user, num_ctx=NUM_CTX):
    body = json.dumps({
        "model": CHAT_MODEL,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "stream": False,
        "options": {"num_ctx": num_ctx},
    }).encode()
    req = urllib.request.Request(OLLAMA + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())["message"]["content"].strip()


def pick_anchor_a(records, seed_query):
    if seed_query:
        qv = norm(embed(seed_query))
        scored = sorted(records, key=lambda r: cosine(qv, r["vec"]), reverse=True)
        return scored[0]
    return random.choice(records)


def pick_anchor_b(records, anchor_a, pool_fraction=0.15, path_filter=None):
    """Deliberately pick from the LEAST similar chunks to anchor_a, excluding its own
    source file (a different chunk of the same doc isn't a real juxtaposition), then
    randomize within that distant pool so repeated runs don't always pair the same two
    things. If path_filter is set, anchor B is constrained to chunks whose source path
    contains it — for deliberately colliding two known-fertile areas (e.g. xete's own
    principles against a specific knowledge-base folder) instead of relying on chance."""
    candidates = [r for r in records if r["path"] != anchor_a["path"]]
    if path_filter:
        filtered = [r for r in candidates if path_filter.lower() in r["path"].lower()]
        if filtered:
            return random.choice(filtered)
        print(f"  (no chunks matched --pair-with '{path_filter}', falling back to distant-pool selection)")
    scored = sorted(candidates, key=lambda r: cosine(anchor_a["vec"], r["vec"]))
    pool_size = max(10, int(len(scored) * pool_fraction))
    return random.choice(scored[:pool_size])


def run_round(records, seed_query, log_path, path_filter=None):
    a = pick_anchor_a(records, seed_query)
    b = pick_anchor_b(records, a, path_filter=path_filter)
    print(f"\n=== Pairing ===\nA: {a['path']}\nB: {b['path']}")

    candidates = []
    for lens_name, lens_prompt in LENSES:
        user = (f"LENS: {lens_prompt}\n\n"
                f"CONTEXT A (from {a['path']}):\n{a['text']}\n\n"
                f"CONTEXT B (from {b['path']}):\n{b['text']}")
        try:
            out = chat(CONNECTION_SYSTEM, user)
        except Exception as e:
            print(f"  [{lens_name}] generation failed: {e}")
            continue
        print(f"  [{lens_name}] {out[:100]}{'...' if len(out) > 100 else ''}")
        candidates.append((lens_name, out))

    if not candidates:
        print("  no candidates generated this round.")
        return None

    candidate_block = "\n\n".join(f"[{name}]\n{text}" for name, text in candidates)
    try:
        verdict_raw = chat(CRITIQUE_SYSTEM, candidate_block)
    except Exception as e:
        print(f"  self-critique failed: {e}")
        return None

    verdict_lens = None
    reason = ""
    for line in verdict_raw.splitlines():
        if line.upper().startswith("VERDICT:"):
            verdict_lens = line.split(":", 1)[1].strip()
        elif line.upper().startswith("REASON:"):
            reason = line.split(":", 1)[1].strip()

    if not verdict_lens or verdict_lens.upper() == "NONE":
        print(f"  filter: NONE survived ({reason or 'no reason given'})")
        return None

    # tolerate formatting noise: brackets, quotes, stray punctuation, case
    verdict_clean = verdict_lens.strip().strip("[]'\"").lower()
    survivor, verdict_lens = next(
        ((text, name) for name, text in candidates if name.lower() == verdict_clean),
        (None, verdict_lens),
    )
    if not survivor:
        print(f"  filter named an unrecognized lens '{verdict_lens}', discarding.")
        return None

    print(f"  filter: SURVIVOR [{verdict_lens}] — {reason}")
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "lens": verdict_lens,
        "reason": reason,
        "connection": survivor,
        "source_a": a["path"],
        "source_b": b["path"],
        "seed": seed_query,
    }
    append_log(log_path, entry)
    return entry


def append_log(log_path, entry):
    is_new = not os.path.exists(log_path)
    with open(log_path, "a", encoding="utf-8") as f:
        if is_new:
            f.write("# xete Brainstorm — Combinatorial Insights Log\n\n"
                    "Auto-generated by `brainstorm_engine.py`. Each entry survived a self-critique "
                    "filter against a pool of discarded candidates — treat these as real candidates "
                    "worth your judgment, not verified truths. Cite sources before trusting a "
                    "specific detail.\n\n---\n\n")
        seed_note = f" (seeded: \"{entry['seed']}\")" if entry["seed"] else ""
        f.write(f"## {entry['ts']} — lens: {entry['lens']}{seed_note}\n\n"
                f"**Sources:** `{entry['source_a']}` × `{entry['source_b']}`\n\n"
                f"**Why it survived:** {entry['reason']}\n\n"
                f"{entry['connection']}\n\n---\n\n")


def main():
    global _embed_model
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", type=int, default=1, help="number of pairings to run")
    ap.add_argument("--seed", type=str, default=None, help="anchor one side on a topic (else fully random)")
    ap.add_argument("--log", type=str, default=DEFAULT_LOG, help="path to the insights log")
    ap.add_argument("--loop", type=int, default=0, help="run continuously for N minutes instead of --rounds")
    ap.add_argument("--pair-with", type=str, default=None,
                     help="force anchor B to come from chunks whose source path contains this substring")
    args = ap.parse_args()

    if not os.path.exists(STORE):
        print(f"No index yet at {STORE}. Run rag_ingest.py first.")
        return
    age_hours = (time.time() - os.path.getmtime(STORE)) / 3600
    if age_hours > 30:
        print(f"(note: index is {age_hours:.0f}h old — nightly reindex may have missed a run; "
              f"`python3 rag_ingest.py` to refresh if recent edits should factor in)\n")
    store = pickle.load(open(STORE, "rb"))
    _embed_model = store["model"]
    records = store["records"]
    print(f"Loaded {len(records)} chunks. Model: {CHAT_MODEL}. Log: {args.log}")

    survivors = 0
    if args.loop:
        deadline = time.time() + args.loop * 60
        i = 0
        while time.time() < deadline:
            i += 1
            print(f"\n--- round {i} (loop mode, {int((deadline - time.time())/60)}m left) ---")
            if run_round(records, args.seed, args.log, path_filter=args.pair_with):
                survivors += 1
    else:
        for i in range(1, args.rounds + 1):
            print(f"\n--- round {i}/{args.rounds} ---")
            if run_round(records, args.seed, args.log, path_filter=args.pair_with):
                survivors += 1

    print(f"\nDone. {survivors} entr{'y' if survivors == 1 else 'ies'} logged to {args.log}")


if __name__ == "__main__":
    main()
