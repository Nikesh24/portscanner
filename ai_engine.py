import glob, os, json

class LocalAI:
    """
    Uses llama-cpp if a .gguf exists in ./models, else a rule-based fallback.
    """
    def __init__(self):
        self.llm = None
        try:
            ggufs = glob.glob(os.path.join("models","*.gguf"))
            if ggufs:
                from llama_cpp import Llama  # type: ignore
                self.llm = Llama(model_path=ggufs[0], n_ctx=2048, n_threads=4)
        except Exception:
            self.llm = None

    def analyze(self, scan_doc: dict, max_tokens: int = 600) -> str:
        ctx = {
            "targets": scan_doc.get("targets", []),
            "results": [
                {"host": h["host"],
                 "open_tcp": [e["port"] for e in h["ports"] if e.get("tcp")=="open"]}
                for h in scan_doc.get("results", [])
            ],
            "summaries": scan_doc.get("summaries", [])
        }
        if self.llm:
            prompt = (
                "You are a security tutor. Explain these port-scan results for a student.\n"
                "Call out common services, obvious risks, and safe next steps.\n"
                f"DATA:\n{json.dumps(ctx)}\n"
                "Be concise and ethical.\n"
            )
            try:
                out = self.llm(prompt, max_tokens=max_tokens)
                return out["choices"][0]["text"].strip()
            except Exception:
                pass

        # fallback
        from common import SERVICE_MAP
        lines = []
        for s in scan_doc.get("summaries", []):
            host = s["host"]
            opens = s.get("open_tcp", [])
            if not opens:
                lines.append(f"{host}: no open TCP ports in the scanned range.")
                continue
            parts = []
            for p in opens:
                svc = SERVICE_MAP.get(p, "unknown")
                hint = {
                    445:"SMB: disable SMBv1, restrict access",
                    3389:"RDP: require NLA, strong auth, restrict by VPN/firewall",
                    22:"SSH: prefer keys, disable password login",
                    80:"HTTP: check admin panels, prefer HTTPS",
                    21:"FTP: avoid plain FTP; prefer SFTP/FTPS"
                }.get(p, "")
                parts.append(f"{p}/tcp ({svc})" + (f" → {hint}" if hint else ""))
            lines.append(f"{host}: open {', '.join(parts)}")
        if not lines:
            lines.append("No notable findings. Many 'filtered' ports may indicate a firewall dropping probes.")
        lines.append("\nNext steps: validate services safely, apply least-exposure firewall rules, keep software updated.")
        return "\n".join(lines)

