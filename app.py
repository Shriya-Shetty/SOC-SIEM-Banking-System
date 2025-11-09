# =============================================================
# 5️⃣ FORENSICS MODULES  (REAL IMPLEMENTATION)
# =============================================================

import traceback
try:
    import psutil
except Exception:
    psutil = None

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except Exception:
    sniff = None


def run_memory_forensics(cust_id: int) -> Tuple[List[dict], int, dict]:
    """
    Real process/memory scanner using psutil.
    Detects abnormal CPU, memory, or suspicious process names.
    Falls back to simulation if psutil unavailable.
    """
    try:
        if psutil is None:
            raise ImportError("psutil not available")

        processes = []
        suspicious_count = 0
        malicious_count = 0

        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info', 'exe']):
            try:
                info = proc.info
                pid = info.get("pid")
                name = info.get("name", "<unknown>")
                user = info.get("username", "UNKNOWN")
                cpu = float(info.get("cpu_percent") or 0)
                mem_mb = round((info.get("memory_info").rss if info.get("memory_info") else 0) / (1024 * 1024), 2)
                exe = info.get("exe") or ""

                status = "safe"
                reason = ""

                # --- Heuristics ---
                if cpu > 50 or mem_mb > 500:
                    status = "suspicious"
                    reason = "High resource usage"
                if any(bad in name.lower() for bad in ["keylogger", "miner", "inject", "hack", "rat"]):
                    status = "malicious"
                    reason = "Known malicious name pattern"
                if ("AppData\\Temp" in exe or "/tmp/" in exe) and exe:
                    status = "suspicious"
                    reason = "Running from temporary directory"

                processes.append({
                    "name": name,
                    "pid": pid,
                    "cpu": round(cpu, 2),
                    "mem": mem_mb,
                    "user": user,
                    "status": status,
                    **({"reason": reason} if reason else {})
                })

                if status in ["suspicious", "malicious"]:
                    suspicious_count += 1
                if status == "malicious":
                    malicious_count += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        total_mem = sum(p["mem"] for p in processes)
        avg_cpu = round(sum(p["cpu"] for p in processes) / max(len(processes), 1), 2)

        metrics = {
            "total_memory_mb": total_mem,
            "avg_cpu_usage": avg_cpu,
            "total_processes": len(processes),
            "suspicious_count": suspicious_count,
            "malicious_count": malicious_count
        }

        # Save to DB
        safe_insert("forensic_memory_scans", {
            "cust_id": cust_id,
            "total_processes": len(processes),
            "suspicious_processes": suspicious_count,
            "malicious_processes": malicious_count,
            "scan_data": {"processes": processes, "metrics": metrics, "scan_time": now_iso()},
            "scan_timestamp": now_iso()
        })

        severity = "critical" if malicious_count > 0 else ("warning" if suspicious_count > 0 else "info")
        log_event(cust_id, "Memory Forensics", "completed",
                  f"Found {suspicious_count} suspicious, {malicious_count} malicious (REAL SCAN)",
                  severity=severity)

        return processes, suspicious_count, metrics

    except Exception as e:
        st.error(f"❌ Memory scan failed: {e}")
        log_event(cust_id, "Memory Forensics", "error", f"Exception: {traceback.format_exc()}", severity="error")
        return [], 0, {}


def run_network_forensics(cust_id: int, capture_seconds: int = 5, max_packets: int = 200) -> Tuple[List[dict], dict]:
    """
    Real network capture using scapy.
    Captures live packets for a few seconds and analyzes them.
    Requires administrator/root privileges.
    """
    try:
        if sniff is None:
            raise ImportError("scapy not available")

        packets_data = []

        def analyze_packet(pkt):
            try:
                proto = "UNKNOWN"
                port = 0
                encrypted = False
                status = "safe"
                reason = ""

                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                else:
                    src = getattr(pkt, "src", "0.0.0.0")
                    dst = getattr(pkt, "dst", "0.0.0.0")

                if TCP in pkt:
                    proto = "TCP"
                    port = pkt[TCP].dport
                elif UDP in pkt:
                    proto = "UDP"
                    port = pkt[UDP].dport
                elif ICMP in pkt:
                    proto = "ICMP"
                    port = 0

                size = len(pkt)

                # Encryption detection by port
                if port in [443, 993, 995, 22]:
                    encrypted = True

                # Suspicious patterns
                if port in [21, 23, 25, 8080, 9050] or dst.startswith("185.") or dst.startswith("10."):
                    status = "suspicious"
                    reason = f"Suspicious port/destination ({port})"

                packets_data.append({
                    "src": src,
                    "dst": dst,
                    "proto": proto,
                    "port": port,
                    "encrypted": encrypted,
                    "size": size,
                    "status": status,
                    **({"reason": reason} if reason else {})
                })
            except Exception:
                pass

        sniff(timeout=capture_seconds, count=max_packets, prn=analyze_packet)

        if not packets_data:
            st.warning("⚠️ No packets captured (need admin/root privileges).")
            return [], {}

        # Metrics
        encrypted_count = sum(1 for p in packets_data if p["encrypted"])
        unencrypted_count = len(packets_data) - encrypted_count
        suspicious_count = sum(1 for p in packets_data if p["status"] == "suspicious")
        total_bytes = sum(p["size"] for p in packets_data)

        proto_dist = defaultdict(int)
        for p in packets_data:
            proto_dist[p["proto"]] += 1

        metrics = {
            "total_packets": len(packets_data),
            "encrypted_packets": encrypted_count,
            "unencrypted_packets": unencrypted_count,
            "suspicious_packets": suspicious_count,
            "total_bytes": total_bytes,
            "protocol_distribution": dict(proto_dist)
        }

        # Save to DB
        safe_insert("forensic_network_captures", {
            "cust_id": cust_id,
            "total_packets": len(packets_data),
            "encrypted_packets": encrypted_count,
            "unencrypted_packets": unencrypted_count,
            "suspicious_packets": suspicious_count,
            "capture_data": {"packets": packets_data, "metrics": metrics, "capture_time": now_iso()},
            "capture_timestamp": now_iso()
        })

        severity = "warning" if suspicious_count > 0 else "info"
        log_event(cust_id, "Network Forensics", "completed",
                  f"Captured {len(packets_data)} packets ({suspicious_count} suspicious, {encrypted_count} encrypted)",
                  severity=severity)

        return packets_data, metrics

    except Exception as e:
        st.error(f"❌ Network capture failed: {e}")
        log_event(cust_id, "Network Forensics", "error", f"Exception: {traceback.format_exc()}", severity="error")
        return [], {}
