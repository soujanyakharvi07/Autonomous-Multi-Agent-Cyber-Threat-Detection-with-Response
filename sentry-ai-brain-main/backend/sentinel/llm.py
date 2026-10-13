"""LLM reasoning. Providers (first key found wins):
  ANTHROPIC_API_KEY -> Claude      GEMINI_API_KEY -> Google Gemini (has a free tier)
No key, or any failure -> deterministic template, labelled source='template' (never faked as an LLM)."""
import os, re, json, urllib.request

SYSTEM = ("You are a defensive SOC analyst assistant. Use ONLY the evidence provided. Be concise (max ~120 words), plain text only with no markdown or asterisks, "
          "explain why the activity is dangerous citing the evidence values, and recommend defensive steps that need "
          "analyst approval. Do not invent facts or give offensive guidance.")

def provider():
    return "anthropic" if os.getenv("ANTHROPIC_API_KEY") else "gemini" if os.getenv("GEMINI_API_KEY") else None

def available(): return provider() is not None

def _post(url, body, headers):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=40) as r: return json.load(r)

def reason(prompt: str, fallback: str, max_tokens=2048):
    p = provider()
    if not p: return dict(text=fallback, source="template", model=None)
    try:
        if p == "anthropic":
            model = os.getenv("SENTINEL_LLM_MODEL", "claude-haiku-4-5-20251001")
            out = _post("https://api.anthropic.com/v1/messages",
                        {"model": model, "max_tokens": max_tokens, "system": SYSTEM, "messages": [{"role": "user", "content": prompt}]},
                        {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"})
            text = "".join(b.get("text", "") for b in out["content"])
        else:
            model = os.getenv("SENTINEL_GEMINI_MODEL", "gemini-flash-latest")
            out = _post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                        {"systemInstruction": {"parts": [{"text": SYSTEM}]}, "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                         "generationConfig": {"maxOutputTokens": max_tokens}},
                        {"x-goog-api-key": os.environ["GEMINI_API_KEY"]})
            text = "".join(x.get("text", "") for x in out["candidates"][0]["content"]["parts"])
        if not text.strip(): raise ValueError("empty LLM response")
        return dict(text=text.strip(), source="llm", model=model)
    except Exception as e:  # network/auth/model-name failure -> honest fallback, error shown in the UI
        return dict(text=fallback, source="template", model=None, error=str(e)[:160])


def reason_json(prompt: str, fallback_obj: dict, max_tokens=2048):
    """Ask the LLM for a JSON object. Falls back (labelled) if no key, failure, or invalid JSON."""
    r = reason(prompt + "\nReturn ONLY one JSON object, no markdown fences.", json.dumps(fallback_obj), max_tokens)
    if r["source"] != "llm": return dict(data=fallback_obj, source="template", model=None, error=r.get("error"))
    t = re.sub(r"^```(?:json)?|```$", "", r["text"].strip(), flags=re.M).strip()
    for cand in (t, (re.search(r"\{.*\}", t, re.S) or [None])[0] if re.search(r"\{.*\}", t, re.S) else None):
        if not cand: continue
        try:
            d = json.loads(cand)
            if isinstance(d, dict): return dict(data=d, source="llm", model=r["model"])
        except Exception: pass
    return dict(data=fallback_obj, source="template", model=None, error="LLM returned invalid JSON")
