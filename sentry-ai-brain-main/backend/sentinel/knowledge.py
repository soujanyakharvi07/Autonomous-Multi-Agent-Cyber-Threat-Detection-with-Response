"""RAG: TF-IDF retrieval over a local defensive knowledge base (sklearn; swap in
sentence-transformers + FAISS by replacing Retriever.embed). Documents are authored
for this project and cite public frameworks by ID; verify against the originals."""
import pathlib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

MITRE = {  # real ATT&CK technique IDs
    "Brute Force": ("T1110", "Brute Force", "Credential Access"),
    "DoS": ("T1499", "Endpoint Denial of Service", "Impact"),
    "DDoS": ("T1498", "Network Denial of Service", "Impact"),
    "Port Scan": ("T1046", "Network Service Discovery", "Discovery"),
    "Botnet": ("T1071", "Application Layer Protocol (C2)", "Command and Control"),
    "Web Attack": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
}
def mitre_url(tid): return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"

DOCS = {
 "brute_force.txt": ("Attack Techniques", "Brute force: many repeated authentication attempts from one source against SSH, FTP or RDP in a short interval, producing many short flows with high SYN/ACK counts and steady packet rate. Confirm failures in authentication logs before responding. Mitigations: account lockout or throttling, multi-factor authentication, key-based SSH, restrict exposure of admin ports to VPN, fail2ban-style rate limiting."),
 "ddos.txt": ("Attack Techniques", "Distributed denial of service: very high packet rate and many SYN flags from many sources toward one service, with little return traffic. Mitigations: upstream scrubbing or CDN, SYN cookies, rate limiting, anycast, autoscaling, coordinate with the ISP."),
 "dos.txt": ("Attack Techniques", "Denial of service from a single source: long-lived or slow connections and elevated request rate against a web service, exhausting workers. Mitigations: per-client connection limits, request timeouts, reverse proxy rate limits, web application firewall rules."),
 "port_scan.txt": ("Network Security", "Port scan: one source probes many destination ports with tiny flows, SYN without completed handshake, few bytes. Often reconnaissance preceding an attack. Mitigations: restrict exposed services, alert on scan patterns, block or tarpit the source after review, verify firewall default-deny."),
 "botnet.txt": ("Malware", "Botnet command and control: periodic beaconing with regular inter-arrival times to unusual ports such as 6667 or 8080, low volume but long idle gaps. Mitigations: isolate the suspected host after approval, inspect DNS and proxy logs, block C2 destinations, reimage if compromise confirmed."),
 "web_attack.txt": ("Attack Techniques", "Web attacks such as SQL injection or XSS arrive as HTTP requests with larger payloads to ports 80, 443 or 8080. Mitigations: input validation, parameterised queries, WAF rules, patch the application, review web server logs."),
 "incident_response.txt": ("Incident Response", "Preserve event evidence, validate scope, identify affected assets, escalate per the organisation's incident response procedure, document actions and require analyst approval before any containment that affects production systems."),
 "authentication_controls.txt": ("Mitigation", "Review rate limits, multi-factor authentication coverage and account lockout policy with service owners; rotate credentials that may have been guessed."),
}
QUERY_BOOST = {"Brute Force": "brute force authentication attempts ssh lockout multi-factor", "DoS": "denial of service connections rate limit",
               "DDoS": "distributed denial of service syn packet rate scrubbing", "Port Scan": "port scan reconnaissance syn probes",
               "Botnet": "botnet beaconing command and control isolate", "Web Attack": "web attack injection waf payload"}

KB_DIR = pathlib.Path(__file__).resolve().parent.parent / "knowledge"

def _chunks(text, size=900):
    out, cur = [], ""
    for para in [p.strip() for p in text.split("\n\n") if p.strip()]:
        if cur and len(cur) + len(para) > size: out.append(cur); cur = ""
        cur = (cur + "\n\n" + para).strip()
    return out + ([cur] if cur else [])

class Retriever:
    def __init__(self):
        docs = dict(DOCS)  # built-in network-attack notes + every .txt/.md file dropped into backend/knowledge/
        for f in sorted(list(KB_DIR.glob("*.txt")) + list(KB_DIR.glob("*.md"))):
            parts = _chunks(f.read_text(encoding="utf-8", errors="replace"))
            for i, part in enumerate(parts): docs[f.name if len(parts) == 1 else f"{f.name}#{i+1}"] = ("Knowledge base", part)
        self.names = list(docs); self.texts = [docs[n][1] for n in self.names]; self.cats = {n: docs[n][0] for n in self.names}
        self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2)).fit(self.texts)
        self.mat = self.vec.transform(self.texts)
    def search(self, query, k=3):
        sims = cosine_similarity(self.vec.transform([query]), self.mat)[0]
        order = sims.argsort()[::-1][:k]
        return [dict(document=self.names[i], category=self.cats[self.names[i]], score=round(float(sims[i]), 3),
                     passage=self.texts[i], source="Local knowledge base") for i in order if sims[i] > 0]
