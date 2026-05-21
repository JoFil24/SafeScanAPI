import requests
import json
from config import OLLAMA_HOST, OLLAMA_MODEL

def build_prompt(scan_results):
    """Build a structured prompt from scan results."""
    nmap_summary = []
    for host in scan_results.get("nmap", []):
        for proto in host.get("protocols", []):
            for port in proto.get("ports", []):
                if port["state"] == "open":
                    nmap_summary.append(
                        f"  - Port {port['port']}/{proto['protocol']}: "
                        f"{port['service']} {port['version']}"
                    )

    zap_summary = []
    for alert in scan_results.get("zap", []):
        if "error" not in alert:
            zap_summary.append(
                f"  - [{alert.get('risk', 'Unknown')} Risk] {alert.get('name')}: "
                f"{alert.get('url')}"
            )

    prompt = f"""You are a cybersecurity analyst. Analyze the following scan results and provide:
1. A short executive summary (2-3 sentences)
2. Top 3 most critical risks found
3. Specific remediation steps for each risk
4. Overall risk rating: Critical / High / Medium / Low

--- NMAP RESULTS (open ports) ---
{chr(10).join(nmap_summary) if nmap_summary else "No open ports found."}

--- ZAP VULNERABILITY RESULTS ---
{chr(10).join(zap_summary) if zap_summary else "No web vulnerabilities found or ZAP was not run."}

Be concise and technical. Format your response clearly with headers."""

    return prompt

def analyze_with_llm(scan_results):
    """Send scan results to local Ollama and return AI analysis."""
    prompt = build_prompt(scan_results)

    try:
        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=120  # LLM can take a while
        )
        response.raise_for_status()
        data = response.json()
        return {
            "status": "success",
            "model": OLLAMA_MODEL,
            "analysis": data.get("response", "No response from model.")
        }
    except requests.exceptions.Timeout:
        return {"status": "error", "error": "LLM timed out after 120 seconds."}
    except Exception as e:
        return {"status": "error", "error": str(e)}
