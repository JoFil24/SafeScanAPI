import nmap
import json
import uuid
import os
import time
import threading
import shutil
from datetime import datetime
from urllib.parse import urlparse
from zapv2 import ZAPv2
from config import RESULTS_DIR, ZAP_API_KEY, ZAP_HOST, ZAP_PORT
from llm import analyze_with_llm

WEB_PORTS = {80, 443, 8080, 8443, 8000, 3000, 5000}

def get_job_path(job_id):
    return os.path.join(RESULTS_DIR, f"{job_id}.json")

def save_job(job_id, data):
    with open(get_job_path(job_id), "w") as f:
        json.dump(data, f, indent=2)

def load_job(job_id):
    path = get_job_path(job_id)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

# ─── Step 1: Nmap ─────────────────────────────────────────────────────────────

def normalize_target(target):
    parsed = urlparse(target if "://" in target else f"http://{target}")
    return parsed.hostname or target, parsed.port, parsed.scheme if parsed.scheme in {"http", "https"} else None


def run_nmap(target):
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap is not installed or not on PATH. Install nmap and try again.")

    host, port, _ = normalize_target(target)
    nm = nmap.PortScanner()

    if port:
        port_args = f"-p {port},1-1000"
    else:
        port_args = "--top-ports 1000"

    nm.scan(hosts=host, arguments=f"-sT -T4 -Pn {port_args}")

    hosts = []
    found_web_ports = []

    for host in nm.all_hosts():
        host_data = {
            "host": host,
            "state": nm[host].state(),
            "protocols": []
        }
        for proto in nm[host].all_protocols():
            ports = []
            for port, info in nm[host][proto].items():
                ports.append({
                    "port": port,
                    "state": info["state"],
                    "service": info["name"],
                    "version": info.get("version", "")
                })
                if info["state"] == "open" and port in WEB_PORTS:
                    scheme = "https" if port in {443, 8443} else "http"
                    found_web_ports.append(f"{scheme}://{host}:{port}")
            host_data["protocols"].append({
                "protocol": proto,
                "ports": ports
            })
        hosts.append(host_data)

    return hosts, found_web_ports

# ─── Step 2: ZAP ──────────────────────────────────────────────────────────────

def run_zap(web_targets):
    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http": f"http://{ZAP_HOST}:{ZAP_PORT}",
            "https": f"http://{ZAP_HOST}:{ZAP_PORT}"
        }
    )

    all_alerts = []

    for target_url in web_targets:
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        context_name = f"context-{host.replace('.', '-') }"

        # Create a context limited to the target host so spider/ascan stay in-scope
        try:
            zap.context.new_context(context_name, apikey=ZAP_API_KEY)
            zap.context.include_in_context(context_name, f".*{host}.*", apikey=ZAP_API_KEY)
        except Exception:
            # Ignore if context APIs are not available or context already exists
            pass

        # Try to set safe spider options; ignore if not available in this ZAP version
        try:
            zap.spider.set_option_max_children(50)
            zap.spider.set_option_max_depth(2)
            zap.spider.set_option_max_duration(60)
        except Exception:
            pass

        # Start spider with context and reduced maxChildren where supported;
        # fall back to a simple scan call if keyword args are rejected.
        try:
            spider_id = zap.spider.scan(target_url, apikey=ZAP_API_KEY, contextName=context_name, maxChildren=50)
        except TypeError:
            spider_id = zap.spider.scan(target_url, apikey=ZAP_API_KEY)

        while int(zap.spider.status(spider_id)) < 100:
            time.sleep(2)

        # Throttle active scanner where possible
        try:
            zap.ascan.set_option_thread_per_host(1)
        except Exception:
            pass

        # Prefer scanning only in-scope; fall back if API doesn't accept the kwarg
        try:
            scan_id = zap.ascan.scan(target_url, apikey=ZAP_API_KEY, recurse=True, inScopeOnly=True)
        except TypeError:
            try:
                scan_id = zap.ascan.scan(target_url, apikey=ZAP_API_KEY, recurse=True)
            except Exception:   
                scan_id = zap.ascan.scan(target_url, apikey=ZAP_API_KEY)

        while int(zap.ascan.status(scan_id)) < 100:
            print(f"ZAP scan progress for {target_url}: {zap.ascan.status(scan_id)}%")
            time.sleep(5)

        alerts = zap.core.alerts(baseurl=target_url)
        for alert in alerts:
            all_alerts.append({
                "url": alert.get("url"),
                "target": target_url,
                "risk": alert.get("risk"),
                "confidence": alert.get("confidence"),
                "name": alert.get("alert"),
                "description": alert.get("description"),
                "solution": alert.get("solution"),
                "cweid": alert.get("cweid"),
                "wascid": alert.get("wascid"),
            })

    return all_alerts

# ─── Step 3: Orchestrator ─────────────────────────────────────────────────────

def run_scan(target, job_id):
    started = datetime.utcnow().isoformat()

    save_job(job_id, {
        "status": "running",
        "stage": "nmap",
        "target": target,
        "started": started
    })

    try:
        # Nmap
        nmap_results, web_targets = run_nmap(target)

        save_job(job_id, {
            "status": "running",
            "stage": "zap" if web_targets else "analyzing",
            "target": target,
            "started": started,
            "results": {"nmap": nmap_results, "web_targets_found": web_targets, "zap": []}
        })

        # ZAP
        zap_results = []
        if web_targets:
            try:
                zap_results = run_zap(web_targets)
            except Exception as zap_err:
                zap_results = [{"error": f"ZAP failed: {str(zap_err)}"}]

        # LLM analysis
        save_job(job_id, {
            "status": "running",
            "stage": "analyzing",
            "target": target,
            "started": started,
            "results": {"nmap": nmap_results, "web_targets_found": web_targets, "zap": zap_results}
        })

        scan_results = {"nmap": nmap_results, "zap": zap_results}
        ai_analysis = analyze_with_llm(scan_results)

        # Final save
        save_job(job_id, {
            "status": "complete",
            "target": target,
            "started": started,
            "finished": datetime.utcnow().isoformat(),
            "results": {
                "nmap": nmap_results,
                "web_targets_found": web_targets,
                "zap": zap_results
            },
            "ai_analysis": ai_analysis
        })

        print(f"Scan complete for {target} (Job ID: {job_id})")

    except Exception as e:
        save_job(job_id, {
            "status": "failed",
            "target": target,
            "error": str(e),
            "finished": datetime.utcnow().isoformat()
        })

def start_scan(target):
    job_id = str(uuid.uuid4())
    thread = threading.Thread(target=run_scan, args=(target, job_id))
    thread.daemon = True
    thread.start()
    return job_id
