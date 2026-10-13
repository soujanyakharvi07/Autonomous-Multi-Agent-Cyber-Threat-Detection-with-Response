# SENTINEL-X backend
Real pipeline: RandomForest detector -> Orchestrator -> Detection / Investigation / Threat Intel (MITRE IDs) /
RAG (TF-IDF) / Response / Explanation (Anthropic LLM if key set, else labelled template).

    pip install -r requirements.txt
    python selftest.py                 # verifies the core without a server
    uvicorn main:app --port 8000

- Real CICIDS2017: POST a CSV to /api/upload (needs the standard CICIDS column names). Without it, a CICIDS-style
  SYNTHETIC set is used and flagged `synthetic: true`; its metrics are NOT real-world accuracy.
- Set ANTHROPIC_API_KEY for LLM reasoning (see .env.example).
- Actions: every response is `pending_approval`. POST /api/actions/{id}/approve executes it: advisory items are
  acknowledged; block_ip appends the IP to data/blocklist.txt for your firewall/SIEM to consume.
