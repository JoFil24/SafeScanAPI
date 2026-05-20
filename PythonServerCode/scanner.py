import nmap
import json
import uuid
import os
import threading
from datetime import datetime
from config import RESULTS_DIR

def get_job_path(job_id):
    return os.path.join(RESULTS_DIR, f"{job_id}.json")

def save_job(job_id, data):
    with open(get_job_path(job_id), "w") as f:
        json.dump(data, f)

def load_job(job_id):
    path = get_job_path(job_id)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def run_nmap(target, job_id):
    save_job(job_id, {
        "status": "running",
        "target": target,
        "started": datetime.utcnow().isoformat()
    })
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sV -T4 --top-ports 1000")

        hosts = []
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
                host_data["protocols"].append({
                    "protocol": proto,
                    "ports": ports
                })
            hosts.append(host_data)

        save_job(job_id, {
            "status": "complete",
            "target": target,
            "finished": datetime.utcnow().isoformat(),
            "results": {"nmap": hosts}
        })
    except Exception as e:
        save_job(job_id, {
            "status": "failed",
            "error": str(e)
        })

def start_scan(target):
    job_id = str(uuid.uuid4())
    thread = threading.Thread(target=run_nmap, args=(target, job_id))
    thread.daemon = True
    thread.start()
    return job_id
