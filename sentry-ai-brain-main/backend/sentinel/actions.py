"""Approval-gated response execution. Nothing runs without explicit approval.
'block_ip' approval appends the IP to a blocklist file (consumed by your firewall/SIEM);
this process never touches the network itself and refuses non-private-range safety exceptions."""
import os, datetime, ipaddress, threading
_lock = threading.Lock(); LOG = []

def execute(action: dict, approver: str = "analyst"):
    if action["kind"] == "advisory":
        action["status"] = "acknowledged"
    else:
        ip = ipaddress.ip_address(action["target"])
        if ip.is_loopback or ip.is_unspecified: raise ValueError("refusing to block loopback/unspecified address")
        path = os.getenv("SENTINEL_BLOCKLIST", "data/blocklist.txt"); os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with _lock, open(path, "a") as f: f.write(f"{ip}  # approved {datetime.datetime.utcnow().isoformat()}Z by {approver}\n")
        action["status"] = "executed"
    action["approved_by"] = approver; LOG.append(dict(action))
    return action
