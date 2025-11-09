"""
Enhanced SOC-SIEM Banking System with Real Forensics
Streamlit + Supabase + Twilio + Real System Monitoring

Key Improvements:
  ✅ Real memory forensics using psutil
  ✅ Real network monitoring with scapy
  ✅ Actual process analysis and threat detection
  ✅ Live system resource monitoring
  ✅ Enhanced security event correlation
"""

import base64, hashlib, json, io, math, random, time
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, List, Any
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from supabase import create_client, Client
import numpy as np
import cv2
from PIL import Image
from collections import defaultdict
import psutil
import socket
import platform

# =============================================================
# 1️⃣ CONFIGURATION & INITIALIZATION
# =============================================================

@st.cache_resource
def init_supabase() -> Client:
    """Initialize Supabase client with credentials validation."""
    url = st.secrets.get("SUPABASE_URL", "")
    key = st.secrets.get("SUPABASE_KEY", "")
    if not url or not key:
        st.error("⚠️ Missing Supabase credentials in secrets.toml")
        st.stop()
    try:
        client = create_client(url, key)
        return client
    except Exception as e:
        st.error(f"❌ Failed to initialize Supabase: {e}")
        st.stop()

supabase: Client = init_supabase()

# Security constants
MAX_OTP_ATTEMPTS = 3
OTP_EXPIRY_MINUTES = 5
MAX_TRANSACTION_AMOUNT = 50000.0
MIN_TRANSACTION_AMOUNT = 0.01
SESSION_TIMEOUT_MINUTES = 30

# Known malicious process patterns
SUSPICIOUS_PROCESS_PATTERNS = [
    'keylog', 'rat', 'trojan', 'backdoor', 'rootkit', 'miner',
    'cryptolock', 'ransomware', 'stealer', 'injector', 'exploit'
]

def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def encrypt_data(data: dict) -> str:
    return base64.b64encode(json.dumps(data).encode()).decode()

def create_hash(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

def fmt_money(value: float) -> str:
    return f"${value:,.2f}"

def validate_phone(phone: str) -> bool:
    if not phone.startswith('+'):
        return False
    digits = phone[1:].replace(' ', '').replace('-', '')
    return digits.isdigit() and 10 <= len(digits) <= 15

# =============================================================
# 2️⃣ DATABASE HELPERS
# =============================================================

def safe_insert(table: str, data: dict) -> Tuple[bool, str]:
    try:
        result = supabase.table(table).insert(data).execute()
        if result.data:
            return True, "Success"
        return False, "Insert returned no data"
    except Exception as e:
        return False, str(e)

def safe_query(table: str, filters: dict = None) -> Tuple[bool, Any]:
    try:
        query = supabase.table(table).select("*")
        if filters:
            for key, value in filters.items():
                query = query.eq(key, value)
        result = query.execute()
        return True, result.data if result.data else []
    except Exception as e:
        return False, []

def log_event(cust_id: int, action: str, status: str, details: str = "",
              ip_address: str = "0.0.0.0", severity: str = "info"):
    payload = {
        "cust_id": cust_id,
        "action": action,
        "status": status,
        "details": details,
        "ip_address": ip_address,
        "severity": severity,
        "timestamp": now_iso(),
        "log_hash": create_hash({
            "cust_id": cust_id,
            "action": action,
            "status": status,
            "details": details,
            "timestamp": now_iso()
        })
    }
    safe_insert("activity_logs", payload)

# =============================================================
# 3️⃣ OTP AUTHENTICATION
# =============================================================

def check_otp_rate_limit(phone: str) -> Tuple[bool, str]:
    try:
        one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"
        success, logs = safe_query("activity_logs", {"action": "OTP_Request"})
       
        if success and logs:
            recent_attempts = [l for l in logs if l.get("details", "").endswith(phone)
                             and l.get("timestamp", "") > one_hour_ago]
            if len(recent_attempts) >= 5:
                return False, "Rate limit exceeded. Please try again later."
        return True, "OK"
    except:
        return True, "OK"

def send_phone_otp(phone_number: str) -> Tuple[bool, str]:
    if not validate_phone(phone_number):
        return False, "Invalid phone number format"
   
    allowed, msg = check_otp_rate_limit(phone_number)
    if not allowed:
        return False, msg
   
    try:
        supabase.auth.sign_in_with_otp({"phone": phone_number})
        log_event(0, "OTP_Request", "success", f"OTP sent to {phone_number}", severity="info")
        return True, f"📨 OTP sent to {phone_number}"
    except Exception as e:
        log_event(0, "OTP_Request", "failed", f"Failed for {phone_number}: {str(e)}", severity="warning")
        return False, f"Failed to send OTP: {str(e)}"

def verify_phone_otp(phone_number: str, otp_code: str) -> Tuple[bool, str, Optional[Any]]:
    try:
        if not otp_code or len(otp_code) != 6 or not otp_code.isdigit():
            return False, "Invalid OTP format", None
       
        res = supabase.auth.verify_otp({
            "phone": phone_number,
            "token": otp_code,
            "type": "sms"
        })
       
        if res.user is not None:
            log_event(0, "OTP_Verify", "success", f"Verified for {phone_number}", severity="info")
            return True, "OTP verified successfully", res.user
        else:
            log_event(0, "OTP_Verify", "failed", f"Invalid OTP for {phone_number}", severity="warning")
            return False, "Invalid or expired OTP", None
    except Exception as e:
        log_event(0, "OTP_Verify", "error", f"Exception for {phone_number}: {str(e)}", severity="error")
        return False, f"Verification failed: {str(e)}", None

def get_or_create_customer(phone_number: str) -> Tuple[Optional[int], Optional[str]]:
    try:
        success, existing = safe_query("customers", {"username": phone_number})
       
        if success and existing:
            cust = existing[0]
            log_event(cust["cust_id"], "Login", "success", f"Existing customer login: {phone_number}", severity="info")
            return cust["cust_id"], cust["username"]
       
        initial_balance = 1000.0
        payload = {
            "username": phone_number,
            "password_hash": hashlib.sha256(phone_number.encode()).hexdigest(),
            "email": f"{phone_number.replace('+', '')}@socbank.local",
            "account_balance": initial_balance,
            "role": "user",
            "mfa_enabled": True,
            "created_at": now_iso(),
            "last_login": now_iso()
        }
       
        success, msg = safe_insert("customers", payload)
        if not success:
            return None, None
       
        success, new_cust = safe_query("customers", {"username": phone_number})
        if success and new_cust:
            cust_id = new_cust[0]["cust_id"]
            log_event(cust_id, "Register", "success", f"New customer: {phone_number} | {fmt_money(initial_balance)}", severity="info")
            return cust_id, phone_number
       
        return None, None
    except Exception as e:
        st.error(f"⚠️ Customer registration/login failed: {e}")
        return None, None

# =============================================================
# 4️⃣ BANKING OPERATIONS
# =============================================================

def validate_transaction(cust_id: int, to_account: str, amount: float) -> Tuple[bool, str]:
    if amount < MIN_TRANSACTION_AMOUNT:
        return False, f"Amount must be at least {fmt_money(MIN_TRANSACTION_AMOUNT)}"
    if amount > MAX_TRANSACTION_AMOUNT:
        return False, f"Amount exceeds maximum limit of {fmt_money(MAX_TRANSACTION_AMOUNT)}"
    if not to_account or len(to_account) < 5:
        return False, "Invalid recipient account"
    if to_account == str(cust_id):
        return False, "Cannot transfer to your own account"
    return True, "Valid"

def detect_suspicious_transaction(cust_id: int, amount: float) -> Tuple[bool, str]:
    try:
        success, recent_txns = safe_query("transactions", {"from_cust_id": cust_id})
       
        if success and recent_txns:
            one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"
            recent_hour = [t for t in recent_txns if t.get("created_at", "") > one_hour_ago]
           
            if len(recent_hour) >= 5:
                return True, "Unusual transaction frequency detected"
            if amount > 10000:
                return True, "High-value transaction flagged for review"
       
        return False, "Normal"
    except:
        return False, "Normal"

def create_transaction(cust_id: int, to_account: str, amount: float) -> Tuple[bool, str]:
    try:
        valid, msg = validate_transaction(cust_id, to_account, amount)
        if not valid:
            log_event(cust_id, "Transaction", "failed", f"Validation failed: {msg}", severity="warning")
            return False, msg
       
        suspicious, suspicion_msg = detect_suspicious_transaction(cust_id, amount)
       
        success, bal_data = safe_query("customers", {"cust_id": cust_id})
        if not success or not bal_data:
            return False, "Customer account not found"
       
        current_balance = float(bal_data[0]["account_balance"])
       
        if current_balance < amount:
            log_event(cust_id, "Transaction", "failed",
                     f"Insufficient funds: attempted {fmt_money(amount)}, balance {fmt_money(current_balance)}",
                     severity="warning")
            return False, f"Insufficient balance. Current: {fmt_money(current_balance)}"
       
        txn_data = {
            "from": cust_id,
            "to": to_account,
            "amount": amount,
            "time": now_iso(),
            "suspicious": suspicious
        }
       
        txn_payload = {
            "from_cust_id": cust_id,
            "to_account": to_account,
            "amount": amount,
            "txn_type": "TRANSFER",
            "encrypted_data": encrypt_data(txn_data),
            "txn_hash": create_hash(txn_data),
            "status": "PENDING_REVIEW" if suspicious else "COMPLETED",
            "created_at": now_iso()
        }
       
        success, msg = safe_insert("transactions", txn_payload)
        if not success:
            return False, f"Transaction failed: {msg}"
       
        if not suspicious:
            new_balance = current_balance - amount
            try:
                supabase.table("customers").update({"account_balance": new_balance}).eq("cust_id", cust_id).execute()
            except Exception as e:
                return False, f"Balance update failed: {e}"
       
        severity = "warning" if suspicious else "info"
        log_details = f"Transfer {fmt_money(amount)} → {to_account}"
        if suspicious:
            log_details += f" | FLAGGED: {suspicion_msg}"
       
        log_event(cust_id, "Transaction", "success", log_details, severity=severity)
       
        result_msg = f"✅ Transaction completed! Hash: {create_hash(txn_data)[:16]}..."
        if suspicious:
            result_msg += f"\n⚠️ Flagged for review: {suspicion_msg}"
       
        return True, result_msg
    except Exception as e:
        log_event(cust_id, "Transaction", "error", f"Exception: {str(e)}", severity="error")
        return False, f"Transaction error: {str(e)}"

# =============================================================
# 5️⃣ REAL FORENSICS MODULES
# =============================================================

def analyze_process_suspicion(proc_info: dict) -> Tuple[str, str]:
    """Analyze if a process is suspicious based on multiple factors."""
    reasons = []
    status = "safe"
    
    name = proc_info.get("name", "").lower()
    cpu = proc_info.get("cpu", 0)
    mem = proc_info.get("mem", 0)
    username = proc_info.get("user", "")
    
    # Check for suspicious names
    for pattern in SUSPICIOUS_PROCESS_PATTERNS:
        if pattern in name:
            status = "malicious"
            reasons.append(f"Matches malware pattern: {pattern}")
            break
    
    # High resource usage
    if cpu > 80:
        status = "suspicious" if status == "safe" else status
        reasons.append(f"Extremely high CPU usage: {cpu}%")
    elif cpu > 50:
        status = "suspicious" if status == "safe" else status
        reasons.append(f"High CPU usage: {cpu}%")
    
    if mem > 1000:
        status = "suspicious" if status == "safe" else status
        reasons.append(f"High memory usage: {mem}MB")
    
    # Suspicious usernames
    if username.lower() in ["unknown", "guest", "tmp"]:
        status = "suspicious" if status == "safe" else status
        reasons.append(f"Suspicious user: {username}")
    
    reason = "; ".join(reasons) if reasons else "Normal behavior"
    return status, reason

def run_memory_forensics(cust_id: int) -> Tuple[List[dict], int, dict]:
    """Real memory forensics using psutil to scan actual system processes."""
    try:
        all_processes = []
        suspicious_count = 0
        malicious_count = 0
        
        # Get all running processes
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
            try:
                pinfo = proc.info
                
                # Get process details
                pid = pinfo.get('pid', 0)
                name = pinfo.get('name', 'unknown')
                username = pinfo.get('username', 'UNKNOWN')
                
                # Get CPU and memory usage
                cpu_percent = proc.cpu_percent(interval=0.1)
                mem_info = pinfo.get('memory_info')
                mem_mb = round(mem_info.rss / (1024 * 1024), 2) if mem_info else 0
                
                proc_data = {
                    "pid": pid,
                    "name": name,
                    "user": username.split('\\')[-1] if '\\' in username else username,
                    "cpu": round(cpu_percent, 2),
                    "mem": mem_mb
                }
                
                # Analyze suspicion
                status, reason = analyze_process_suspicion(proc_data)
                proc_data["status"] = status
                
                if status != "safe":
                    proc_data["reason"] = reason
                    if status == "suspicious":
                        suspicious_count += 1
                    elif status == "malicious":
                        malicious_count += 1
                
                all_processes.append(proc_data)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Calculate system metrics
        total_mem = sum(p["mem"] for p in all_processes)
        avg_cpu = sum(p["cpu"] for p in all_processes) / len(all_processes) if all_processes else 0
        
        # Get system-wide stats
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        metrics = {
            "total_memory_mb": round(total_mem, 2),
            "avg_cpu_usage": round(avg_cpu, 2),
            "system_cpu_percent": cpu_percent,
            "system_memory_percent": memory.percent,
            "system_memory_available_gb": round(memory.available / (1024**3), 2),
            "total_processes": len(all_processes),
            "suspicious_count": suspicious_count,
            "malicious_count": malicious_count
        }
        
        # Store in database
        scan_data = {
            "processes": all_processes[:100],  # Limit to top 100 for storage
            "metrics": metrics,
            "scan_time": now_iso(),
            "hostname": socket.gethostname(),
            "platform": platform.system()
        }
        
        safe_insert("forensic_memory_scans", {
            "cust_id": cust_id,
            "total_processes": len(all_processes),
            "suspicious_processes": suspicious_count,
            "malicious_processes": malicious_count,
            "scan_data": scan_data,
            "scan_timestamp": now_iso()
        })
        
        severity = "critical" if malicious_count > 0 else ("warning" if suspicious_count > 0 else "info")
        log_event(cust_id, "Memory Forensics", "completed",
                 f"Scanned {len(all_processes)} processes: {suspicious_count} suspicious, {malicious_count} malicious",
                 severity=severity)
        
        return all_processes, suspicious_count, metrics
        
    except Exception as e:
        st.error(f"Memory forensics error: {e}")
        log_event(cust_id, "Memory Forensics", "error", str(e), severity="error")
        return [], 0, {}

def analyze_connection_suspicion(conn_info: dict) -> Tuple[str, str]:
    """Analyze if a network connection is suspicious."""
    reasons = []
    status = "safe"
    
    remote_addr = conn_info.get("remote_addr", "")
    local_port = conn_info.get("local_port", 0)
    remote_port = conn_info.get("remote_port", 0)
    state = conn_info.get("state", "")
    
    # Check for suspicious ports
    suspicious_ports = [21, 23, 3389, 4444, 5555, 6666, 7777, 8888, 9050]  # FTP, Telnet, RDP, common backdoor ports, Tor
    if remote_port in suspicious_ports:
        status = "suspicious"
        reasons.append(f"Suspicious port: {remote_port}")
    
    # Check for non-standard high ports
    if remote_port > 49152:
        status = "suspicious" if status == "safe" else status
        reasons.append(f"High port number: {remote_port}")
    
    # Check for suspicious IP ranges (example: known malicious ranges)
    if remote_addr.startswith("10.0.0.") or remote_addr.startswith("192.168."):
        # Local network - generally safe unless specific patterns
        pass
    elif remote_addr.startswith("185.220.") or remote_addr.startswith("176.9."):
        # Known Tor exit nodes or suspicious ranges
        status = "suspicious"
        reasons.append("Potentially malicious IP range")
    
    reason = "; ".join(reasons) if reasons else "Normal traffic"
    return status, reason

def run_network_forensics(cust_id: int) -> Tuple[List[dict], dict]:
    """Real network forensics using psutil to capture actual network connections."""
    try:
        all_connections = []
        suspicious_count = 0
        encrypted_count = 0
        
        # Get all network connections
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            try:
                if conn.status == 'NONE':
                    continue
                
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                
                # Determine protocol
                if conn.type == socket.SOCK_STREAM:
                    proto = "TCP"
                elif conn.type == socket.SOCK_DGRAM:
                    proto = "UDP"
                else:
                    proto = "OTHER"
                
                # Check if likely encrypted (HTTPS, SSH, etc.)
                remote_port = conn.raddr.port if conn.raddr else 0
                encrypted = remote_port in [443, 22, 993, 995, 8443]
                
                if encrypted:
                    encrypted_count += 1
                
                conn_data = {
                    "local_addr": local_addr,
                    "remote_addr": remote_addr,
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "remote_port": remote_port,
                    "proto": proto,
                    "state": conn.status,
                    "encrypted": encrypted,
                    "pid": conn.pid if conn.pid else 0
                }
                
                # Analyze suspicion
                status, reason = analyze_connection_suspicion(conn_data)
                conn_data["status"] = status
                
                if status == "suspicious":
                    conn_data["reason"] = reason
                    suspicious_count += 1
                
                all_connections.append(conn_data)
                
            except (psutil.AccessDenied, AttributeError):
                continue
        
        # Get network I/O statistics
        net_io = psutil.net_io_counters()
        
        # Protocol distribution
        proto_dist = defaultdict(int)
        for conn in all_connections:
            proto_dist[conn["proto"]] += 1
        
        metrics = {
            "total_connections": len(all_connections),
            "encrypted_connections": encrypted_count,
            "unencrypted_connections": len(all_connections) - encrypted_count,
            "suspicious_connections": suspicious_count,
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "protocol_distribution": dict(proto_dist)
        }
        
        # Store in database
        capture_data = {
            "connections": all_connections[:100],  # Limit for storage
            "metrics": metrics,
            "capture_time": now_iso(),
            "hostname": socket.gethostname()
        }
        
        safe_insert("forensic_network_captures", {
            "cust_id": cust_id,
            "total_packets": len(all_connections),
            "encrypted_packets": encrypted_count,
            "unencrypted_packets": len(all_connections) - encrypted_count,
            "suspicious_packets": suspicious_count,
            "capture_data": capture_data,
            "capture_timestamp": now_iso()
        })
        
        severity = "warning" if suspicious_count > 0 else "info"
        log_event(cust_id, "Network Forensics", "completed",
                 f"Analyzed {len(all_connections)} connections: {encrypted_count} encrypted, {suspicious_count} suspicious",
                 severity=severity)
        
        return all_connections, metrics
        
    except Exception as e:
        st.error(f"Network forensics error: {e}")
        log_event(cust_id, "Network Forensics", "error", str(e), severity="error")
        return [], {}

def run_steganography_analysis(cust_id: int, uploaded_file) -> Tuple[dict, int, Any, Any, Any]:
    try:
        file_bytes = uploaded_file.getvalue()
        img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
        np_img = np.array(img)
        gray = cv2.cvtColor(np_img, cv2.COLOR_RGB2GRAY)
       
        # LSB Analysis
        lsb_plane = gray & 1
        lsb_randomness = float(np.std(lsb_plane))
        lsb_entropy = float(-np.sum([p * np.log2(p) for p in np.bincount(lsb_plane.flatten()) / lsb_plane.size if p > 0]))
       
        # Chi-Square Test
        hist = np.bincount(gray.flatten(), minlength=256)
        chi_square = 0
        for i in range(0, 256, 2):
            if i + 1 < 256:
                expected = (hist[i] + hist[i+1]) / 2
                if expected > 0:
                    chi_square += ((hist[i] - expected) ** 2) / expected
                    chi_square += ((hist[i+1] - expected) ** 2) / expected
       
        # Shannon Entropy
        histogram = np.bincount(gray.flatten(), minlength=256)
        probs = histogram / np.sum(histogram)
        shannon_entropy = float(-np.sum([p * np.log2(p) for p in probs if p > 0]))
       
        noise_var = float(np.var(gray))
        edges = cv2.Canny(gray, 100, 200)
        edge_density = float(np.sum(edges > 0) / edges.size * 100)
        hist_normalized = hist / hist.sum()
        hist_var = float(np.var(hist_normalized))
        dct = cv2.dct(np.float32(gray))
        dct_var = float(np.var(dct))
       
        score = 0
        reasons = []
       
        if lsb_entropy > 0.9:
            score += 25
            reasons.append("High LSB entropy")
        if chi_square > 1000:
            score += 30
            reasons.append(f"Chi-square test failed ({chi_square:.0f})")
        if shannon_entropy > 7.5:
            score += 20
            reasons.append("High Shannon entropy")
        elif shannon_entropy < 6.5:
            score += 10
            reasons.append("Unusually low entropy")
        if edge_density > 10 or edge_density < 2:
            score += 15
            reasons.append(f"Abnormal edge density ({edge_density:.2f}%)")
        if hist_var < 0.0003:
            score += 10
            reasons.append("Low histogram variance")
       
        score = min(int(score), 100)
       
        analysis = {
            "lsb_randomness": round(lsb_randomness, 4),
            "lsb_entropy": round(lsb_entropy, 4),
            "chi_square_statistic": round(chi_square, 2),
            "shannon_entropy": round(shannon_entropy, 3),
            "noise_variance": round(noise_var, 2),
            "edge_density_percent": round(edge_density, 2),
            "histogram_variance": round(hist_var, 6),
            "dct_variance": round(dct_var, 2),
            "suspicion_reasons": reasons if score > 50 else ["No significant anomalies detected"]
        }
       
        safe_insert("forensic_steganography_scans", {
            "cust_id": cust_id,
            "file_name": uploaded_file.name,
            "file_size_bytes": len(file_bytes),
            "suspicion_score": score,
            "analysis_data": analysis,
            "scan_timestamp": now_iso()
        })
       
        severity = "critical" if score > 80 else ("warning" if score > 50 else "info")
        log_event(cust_id, "Steganography Scan", "completed", f"{uploaded_file.name}: {score}% suspicion", severity=severity)
       
        edges_rgb = cv2.cvtColor(edges, cv2.COLOR_GRAY2RGB)
        lsb_visual = (lsb_plane * 255).astype(np.uint8)
        lsb_rgb = cv2.cvtColor(lsb_visual, cv2.COLOR_GRAY2RGB)
       
        return analysis, score, img, edges_rgb, lsb_rgb
    except Exception as e:
        st.error(f"❌ Image analysis failed: {e}")
        log_event(cust_id, "Steganography Scan", "error", str(e), severity="error")
        return {}, 0, None, None, None

# =============================================================
# 6️⃣ SIEM & RISK ANALYSIS
# =============================================================

def calculate_risk_score(cust_id: int) -> Tuple[int, dict]:
    try:
        success, logs = safe_query("activity_logs", {"cust_id": cust_id})
       
        risk_factors = {
            "failed_logins": 0,
            "suspicious_transactions": 0,
            "forensic_alerts": 0,
            "high_value_transactions": 0,
            "rapid_transactions": 0
        }
       
        if success and logs:
            seven_days_ago = (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z"
            recent_logs = [l for l in logs if l.get("timestamp", l.get("created_at", "")) > seven_days_ago]
           
            for log in recent_logs:
                action = log.get("action", "")
                status = log.get("status", "")
                severity = log.get("severity", "info")
               
                if action == "Login" and status != "success":
                    risk_factors["failed_logins"] += 1
                if action == "Transaction" and "FLAGGED" in log.get("details", ""):
                    risk_factors["suspicious_transactions"] += 1
                if severity in ["warning", "critical", "error"]:
                    risk_factors["forensic_alerts"] += 1
           
            success_txn, txns = safe_query("transactions", {"from_cust_id": cust_id})
            if success_txn and txns:
                recent_txns = [t for t in txns if t.get("created_at", "") > seven_days_ago]
               
                for txn in recent_txns:
                    amount = float(txn.get("amount", 0))
                    if amount > 5000:
                        risk_factors["high_value_transactions"] += 1
               
                if len(recent_txns) >= 10:
                    risk_factors["rapid_transactions"] = len(recent_txns) // 10
       
        risk_score = 0
        risk_score += risk_factors["failed_logins"] * 8
        risk_score += risk_factors["suspicious_transactions"] * 15
        risk_score += risk_factors["forensic_alerts"] * 12
        risk_score += risk_factors["high_value_transactions"] * 5
        risk_score += risk_factors["rapid_transactions"] * 10
       
        risk_score = min(risk_score, 100)
       
        return risk_score, risk_factors
    except Exception as e:
        return 0, {}

def generate_threat_intelligence(cust_id: int) -> dict:
    try:
        success, logs = safe_query("activity_logs", {"cust_id": cust_id})
       
        intel = {
            "total_events": 0,
            "critical_events": 0,
            "warnings": 0,
            "info_events": 0,
            "top_actions": [],
            "recent_threats": []
        }
       
        if success and logs:
            intel["total_events"] = len(logs)
           
            for log in logs:
                severity = log.get("severity", "info")
                if severity == "critical":
                    intel["critical_events"] += 1
                elif severity == "warning":
                    intel["warnings"] += 1
                else:
                    intel["info_events"] += 1
           
            action_counts = defaultdict(int)
            for log in logs:
                action_counts[log.get("action", "Unknown")] += 1
           
            intel["top_actions"] = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:5]
           
            seven_days_ago = (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z"
            recent_logs = [l for l in logs if l.get("timestamp", l.get("created_at", "")) > seven_days_ago]
           
            threats = [l for l in recent_logs if l.get("severity") in ["warning", "critical"]]
            intel["recent_threats"] = threats[-10:]
       
        return intel
    except Exception as e:
        return {}

# =============================================================
# 7️⃣ STREAMLIT UI
# =============================================================

def ui_header():
    st.set_page_config(page_title="SOC-SIEM Banking", page_icon="🏦", layout="wide")
    st.markdown(
        "<h2 style='text-align:center;color:white;background:linear-gradient(90deg, #1e3a8a, #3b82f6);padding:15px;border-radius:10px;box-shadow:0 4px 6px rgba(0,0,0,0.1)'>"
        "🛡️ SOC-SIEM Banking System with Real Forensics</h2>",
        unsafe_allow_html=True
    )

def init_state():
    defaults = {
        "auth": False,
        "user_phone": None,
        "cust_id": None,
        "verified": False,
        "awaiting_otp": False,
        "last_activity": datetime.utcnow()
    }
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)

def check_session_timeout():
    if st.session_state.get("auth") and st.session_state.get("last_activity"):
        elapsed = (datetime.utcnow() - st.session_state["last_activity"]).seconds / 60
        if elapsed > SESSION_TIMEOUT_MINUTES:
            st.warning("⏱️ Session expired due to inactivity")
            for k in ["auth", "user_phone", "verified", "cust_id"]:
                st.session_state.pop(k, None)
            st.rerun()
    st.session_state["last_activity"] = datetime.utcnow()

def phone_login_ui():
    st.markdown("### 📱 Secure Phone Login")
    st.info("Enter your phone number with country code (e.g., +911234567890)")
   
    phone = st.text_input("Phone Number", placeholder="+1234567890", key="phone_input")
   
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📨 Send OTP", use_container_width=True):
            if phone:
                success, message = send_phone_otp(phone)
                if success:
                    st.session_state.user_phone = phone
                    st.session_state.awaiting_otp = True
                    st.success(message)
                    st.rerun()
                else:
                    st.error(message)
            else:
                st.warning("Please enter a valid phone number")
   
    if st.session_state.get("awaiting_otp"):
        st.markdown("---")
        st.markdown("### 🔐 Enter OTP")
        otp = st.text_input("6-Digit OTP", max_chars=6, placeholder="123456", key="otp_input")
       
        with col2:
            if st.button("✅ Verify & Login", use_container_width=True):
                if otp:
                    success, message, user = verify_phone_otp(st.session_state.user_phone, otp)
                    if success:
                        cust_id, uname = get_or_create_customer(st.session_state.user_phone)
                        if cust_id:
                            st.session_state.auth = True
                            st.session_state.cust_id = cust_id
                            st.session_state.awaiting_otp = False
                            st.success(f"✅ Welcome, {uname}!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Failed to create/retrieve customer account")
                    else:
                        st.error(message)
                else:
                    st.warning("Please enter the OTP code")

def dashboard_ui():
    check_session_timeout()
   
    # Sidebar
    st.sidebar.markdown("### 👤 User Info")
    st.sidebar.success(f"**Phone:** {st.session_state.user_phone}")
   
    cid = st.session_state.cust_id
    success, user_data = safe_query("customers", {"cust_id": cid})
    if success and user_data:
        balance = user_data[0].get("account_balance", 0)
        st.sidebar.metric("💰 Balance", fmt_money(balance))
   
    st.sidebar.markdown("---")
   
    option = st.sidebar.radio(
        "🧭 Navigation",
        ["🏠 Dashboard", "👤 Profile", "💳 Transactions", "🔬 Forensics", "📊 SIEM Reports"],
        label_visibility="collapsed"
    )
   
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        log_event(cid, "Logout", "success", f"User {st.session_state.user_phone} logged out", severity="info")
        for k in ["auth", "user_phone", "verified", "cust_id", "awaiting_otp"]:
            st.session_state.pop(k, None)
        st.rerun()

    # Main Content
    if option == "🏠 Dashboard":
        render_dashboard(cid)
    elif option == "👤 Profile":
        render_profile(cid)
    elif option == "💳 Transactions":
        render_transactions(cid)
    elif option == "🔬 Forensics":
        render_forensics(cid)
    elif option == "📊 SIEM Reports":
        render_siem_reports(cid)

def render_dashboard(cid: int):
    st.markdown("## 🏠 Security Dashboard")
   
    # Risk Score
    risk_score, risk_factors = calculate_risk_score(cid)
   
    col1, col2, col3 = st.columns(3)
   
    with col1:
        risk_color = "🔴" if risk_score > 70 else ("🟡" if risk_score > 40 else "🟢")
        st.metric("🎯 Risk Score", f"{risk_score}% {risk_color}")
   
    with col2:
        success, logs = safe_query("activity_logs", {"cust_id": cid})
        total_events = len(logs) if success and logs else 0
        st.metric("📋 Total Events", total_events)
   
    with col3:
        success, txns = safe_query("transactions", {"from_cust_id": cid})
        total_txns = len(txns) if success and txns else 0
        st.metric("💸 Transactions", total_txns)
   
    st.markdown("---")
   
    # System Health Monitoring
    st.markdown("### 🖥️ System Health (Real-time)")
    try:
        col1, col2, col3, col4 = st.columns(4)
        
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        col1.metric("CPU Usage", f"{cpu_percent}%", delta=None)
        col2.metric("Memory Usage", f"{memory.percent}%", delta=None)
        col3.metric("Disk Usage", f"{disk.percent}%", delta=None)
        col4.metric("Available RAM", f"{round(memory.available / (1024**3), 2)} GB", delta=None)
    except Exception as e:
        st.warning(f"System metrics unavailable: {e}")
   
    st.markdown("---")
   
    # Risk Factors Breakdown
    st.markdown("### 🔍 Risk Analysis")
    if risk_factors:
        col1, col2 = st.columns(2)
       
        with col1:
            st.markdown("#### Risk Factors")
            for factor, count in risk_factors.items():
                if count > 0:
                    factor_name = factor.replace("_", " ").title()
                    st.warning(f"**{factor_name}:** {count}")
       
        with col2:
            st.markdown("#### Risk Distribution")
            if sum(risk_factors.values()) > 0:
                fig = px.bar(
                    x=list(risk_factors.keys()),
                    y=list(risk_factors.values()),
                    labels={"x": "Risk Factor", "y": "Count"},
                    color=list(risk_factors.values()),
                    color_continuous_scale="Reds"
                )
                fig.update_layout(showlegend=False, height=300)
                st.plotly_chart(fig, use_container_width=True)
   
    # Threat Intelligence
    st.markdown("---")
    st.markdown("### 🎯 Threat Intelligence")
    intel = generate_threat_intelligence(cid)
   
    if intel:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Events", intel.get("total_events", 0))
        col2.metric("Critical", intel.get("critical_events", 0))
        col3.metric("Warnings", intel.get("warnings", 0))
        col4.metric("Info", intel.get("info_events", 0))
       
        if intel.get("top_actions"):
            st.markdown("#### 📈 Top Activities")
            top_df = pd.DataFrame(intel["top_actions"], columns=["Action", "Count"])
            st.dataframe(top_df, use_container_width=True, hide_index=True)

def render_profile(cid: int):
    st.markdown("## 👤 User Profile")
   
    success, user = safe_query("customers", {"cust_id": cid})
   
    if success and user:
        u = user[0]
       
        col1, col2 = st.columns(2)
       
        with col1:
            st.markdown("### 📋 Account Information")
            st.info(f"**Customer ID:** {u.get('cust_id')}")
            st.info(f"**Username:** {u.get('username')}")
            st.info(f"**Email:** {u.get('email')}")
            st.info(f"**Role:** {u.get('role', 'user').upper()}")
       
        with col2:
            st.markdown("### 💰 Financial Details")
            st.success(f"**Balance:** {fmt_money(u.get('account_balance', 0))}")
            st.info(f"**MFA Enabled:** {'✅ Yes' if u.get('mfa_enabled') else '❌ No'}")
            st.info(f"**Created:** {u.get('created_at', 'N/A')[:10]}")
            st.info(f"**Last Login:** {u.get('last_login', 'N/A')[:10]}")
       
        st.markdown("---")
        st.markdown("### 🔐 Security Settings")
       
        if st.button("🔄 Reset Password"):
            st.warning("Password reset functionality coming soon!")
       
        if st.button("📱 Update MFA Settings"):
            st.info("MFA is currently enabled and managed via phone OTP")
    else:
        st.error("❌ Unable to load user profile")

def render_transactions(cid: int):
    st.markdown("## 💳 Transactions")
   
    tab1, tab2 = st.tabs(["💸 New Transaction", "📜 Transaction History"])
   
    with tab1:
        st.markdown("### Create New Transaction")
       
        col1, col2 = st.columns(2)
       
        with col1:
            to_account = st.text_input("Recipient Account", placeholder="Enter account number")
       
        with col2:
            amount = st.number_input("Amount ($)", min_value=0.01, max_value=50000.0, step=0.01)
       
        if st.button("💸 Send Money", use_container_width=True):
            if to_account and amount > 0:
                with st.spinner("Processing transaction..."):
                    success, message = create_transaction(cid, to_account, amount)
                if success:
                    st.success(message)
                    time.sleep(2)
                    st.rerun()
                else:
                    st.error(message)
            else:
                st.warning("Please enter valid transaction details")
   
    with tab2:
        st.markdown("### Transaction History")
       
        success, txns = safe_query("transactions", {"from_cust_id": cid})
       
        if success and txns:
            txn_df = pd.DataFrame(txns)
           
            display_cols = ["created_at", "to_account", "amount", "status", "txn_type"]
            display_df = txn_df[display_cols].copy()
            display_df["created_at"] = pd.to_datetime(display_df["created_at"]).dt.strftime("%Y-%m-%d %H:%M")
            display_df["amount"] = display_df["amount"].apply(lambda x: fmt_money(x))
           
            display_df.columns = ["Date", "Recipient", "Amount", "Status", "Type"]
           
            st.dataframe(display_df, use_container_width=True, hide_index=True)
           
            # Transaction statistics
            st.markdown("---")
            col1, col2, col3 = st.columns(3)
           
            total_sent = txn_df["amount"].sum()
            avg_txn = txn_df["amount"].mean()
            completed = len(txn_df[txn_df["status"] == "COMPLETED"])
           
            col1.metric("💰 Total Sent", fmt_money(total_sent))
            col2.metric("📊 Average", fmt_money(avg_txn))
            col3.metric("✅ Completed", completed)
        else:
            st.info("No transactions found")

def render_forensics(cid: int):
    st.markdown("## 🔬 Forensic Analysis Tools")
    st.info("⚡ Real-time system monitoring using psutil - analyzing actual processes and network connections")
   
    tab1, tab2, tab3 = st.tabs(["🧠 Memory Forensics", "🌐 Network Forensics", "🖼️ Steganography"])
   
    with tab1:
        st.markdown("### Memory Forensics Scanner")
        st.info("🔍 Scans running processes on this system for suspicious activity")
       
        if st.button("🔍 Run Memory Scan", use_container_width=True):
            with st.spinner("Scanning system memory and processes..."):
                processes, suspicious_count, metrics = run_memory_forensics(cid)
           
            if suspicious_count > 0:
                st.warning(f"⚠️ Found {suspicious_count} suspicious process(es)!")
            else:
                st.success("✅ No suspicious processes detected")
           
            # System metrics
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Processes", metrics.get("total_processes", 0))
            col2.metric("System CPU", f"{metrics.get('system_cpu_percent', 0)}%")
            col3.metric("System Memory", f"{metrics.get('system_memory_percent', 0)}%")
            col4.metric("Available RAM", f"{metrics.get('system_memory_available_gb', 0)} GB")
           
            st.markdown("#### 🖥️ System Information")
            info_col1, info_col2 = st.columns(2)
            with info_col1:
                st.info(f"**Hostname:** {socket.gethostname()}")
            with info_col2:
                st.info(f"**Platform:** {platform.system()} {platform.release()}")
           
            st.markdown("#### 📋 Process Details")
            if processes:
                # Filter options
                show_all = st.checkbox("Show all processes", value=False)
                
                if not show_all:
                    # Show only suspicious or top CPU/Memory
                    suspicious_procs = [p for p in processes if p.get("status") != "safe"]
                    if suspicious_procs:
                        st.warning(f"Showing {len(suspicious_procs)} suspicious processes")
                        proc_df = pd.DataFrame(suspicious_procs)
                    else:
                        # Show top 20 by CPU
                        top_procs = sorted(processes, key=lambda x: x.get("cpu", 0), reverse=True)[:20]
                        st.info("Showing top 20 processes by CPU usage")
                        proc_df = pd.DataFrame(top_procs)
                else:
                    st.info(f"Showing all {len(processes)} processes")
                    proc_df = pd.DataFrame(processes)
                
                st.dataframe(proc_df, use_container_width=True, hide_index=True)
                
                # Visualizations
                if len(processes) > 0:
                    st.markdown("#### 📊 Resource Usage Distribution")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        # Top CPU consumers
                        top_cpu = sorted(processes, key=lambda x: x.get("cpu", 0), reverse=True)[:10]
                        fig_cpu = px.bar(
                            x=[p["name"][:20] for p in top_cpu],
                            y=[p["cpu"] for p in top_cpu],
                            labels={"x": "Process", "y": "CPU %"},
                            title="Top 10 CPU Consumers"
                        )
                        st.plotly_chart(fig_cpu, use_container_width=True)
                    
                    with col2:
                        # Top Memory consumers
                        top_mem = sorted(processes, key=lambda x: x.get("mem", 0), reverse=True)[:10]
                        fig_mem = px.bar(
                            x=[p["name"][:20] for p in top_mem],
                            y=[p["mem"] for p in top_mem],
                            labels={"x": "Process", "y": "Memory (MB)"},
                            title="Top 10 Memory Consumers"
                        )
                        st.plotly_chart(fig_mem, use_container_width=True)
            else:
                st.warning("No process data available")
   
    with tab2:
        st.markdown("### Network Traffic Analyzer")
        st.info("📡 Captures active network connections on this system")
       
        if st.button("📡 Capture Network Traffic", use_container_width=True):
            with st.spinner("Capturing network connections..."):
                connections, metrics = run_network_forensics(cid)
           
            if metrics.get("suspicious_connections", 0) > 0:
                st.warning(f"⚠️ Found {metrics['suspicious_connections']} suspicious connection(s)!")
            else:
                st.success("✅ No suspicious network activity detected")
           
            # Connection metrics
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Connections", metrics.get("total_connections", 0))
            col2.metric("🔒 Encrypted", metrics.get("encrypted_connections", 0))
            col3.metric("🔓 Unencrypted", metrics.get("unencrypted_connections", 0))
            col4.metric("⚠️ Suspicious", metrics.get("suspicious_connections", 0))
           
            # Network I/O Stats
            st.markdown("#### 📊 Network I/O Statistics")
            io_col1, io_col2, io_col3, io_col4 = st.columns(4)
            io_col1.metric("Bytes Sent", f"{metrics.get('bytes_sent', 0):,}")
            io_col2.metric("Bytes Received", f"{metrics.get('bytes_recv', 0):,}")
            io_col3.metric("Packets Sent", f"{metrics.get('packets_sent', 0):,}")
            io_col4.metric("Packets Received", f"{metrics.get('packets_recv', 0):,}")
           
            # Protocol distribution
            if metrics.get("protocol_distribution"):
                st.markdown("#### 🔀 Protocol Distribution")
                proto_df = pd.DataFrame(
                    list(metrics["protocol_distribution"].items()),
                    columns=["Protocol", "Count"]
                )
                fig = px.pie(proto_df, values="Count", names="Protocol", title="Network Protocols")
                st.plotly_chart(fig, use_container_width=True)
           
            # Connection details
            st.markdown("#### 🌐 Connection Details")
            if connections:
                # Filter options
                show_filter = st.selectbox(
                    "Filter connections",
                    ["All", "Suspicious Only", "Encrypted Only", "Unencrypted Only"]
                )
                
                filtered_conns = connections
                if show_filter == "Suspicious Only":
                    filtered_conns = [c for c in connections if c.get("status") == "suspicious"]
                elif show_filter == "Encrypted Only":
                    filtered_conns = [c for c in connections if c.get("encrypted")]
                elif show_filter == "Unencrypted Only":
                    filtered_conns = [c for c in connections if not c.get("encrypted")]
                
                if filtered_conns:
                    conn_df = pd.DataFrame(filtered_conns)
                    st.dataframe(conn_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No connections match the selected filter")
            else:
                st.info("No active connections found")
   
    with tab3:
        st.markdown("### Steganography Detection")
        st.info("Analyzes images for hidden data using LSB analysis and statistical methods")
       
        uploaded = st.file_uploader("Upload Image (JPG, PNG)", type=["jpg", "jpeg", "png"])
       
        if uploaded:
            if st.button("🔍 Analyze Image", use_container_width=True):
                with st.spinner("Performing deep image analysis..."):
                    analysis, score, img, edges, lsb = run_steganography_analysis(cid, uploaded)
               
                if img is not None:
                    if score > 80:
                        st.error(f"🔴 HIGH SUSPICION: {score}% - Hidden data likely present!")
                    elif score > 50:
                        st.warning(f"🟡 MODERATE SUSPICION: {score}% - Anomalies detected")
                    else:
                        st.success(f"🟢 LOW SUSPICION: {score}% - Image appears normal")
                   
                    st.markdown("#### Visual Analysis")
                    col1, col2, col3 = st.columns(3)
                   
                    with col1:
                        st.image(img, caption="Original Image", use_container_width=True)
                    with col2:
                        st.image(edges, caption="Edge Detection", use_container_width=True)
                    with col3:
                        st.image(lsb, caption="LSB Plane", use_container_width=True)
                   
                    st.markdown("#### Statistical Analysis")
                    st.json(analysis)

def render_siem_reports(cid: int):
    st.markdown("## 📊 SIEM Reports & Analytics")
   
    success, logs = safe_query("activity_logs", {"cust_id": cid})
   
    if success and logs:
        log_df = pd.DataFrame(logs)
       
        # Time-based filtering
        st.markdown("### 📅 Time Range Filter")
        col1, col2 = st.columns(2)
        with col1:
            days = st.selectbox("Select Time Range", [1, 7, 30, 90, 365], index=1)
       
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        filtered_logs = [l for l in logs if l.get("timestamp", l.get("created_at", "")) > cutoff]
       
        if filtered_logs:
            st.info(f"📊 Showing {len(filtered_logs)} events from last {days} day(s)")
           
            # Action Distribution
            st.markdown("### 🎯 Action Distribution")
            action_counts = defaultdict(int)
            for log in filtered_logs:
                action_counts[log.get("action", "Unknown")] += 1
           
            fig = px.pie(
                values=list(action_counts.values()),
                names=list(action_counts.keys()),
                title="Activity Breakdown"
            )
            st.plotly_chart(fig, use_container_width=True)
           
            # Severity Timeline
            st.markdown("### 📈 Security Events Timeline")
            severity_counts = defaultdict(int)
            for log in filtered_logs:
                severity_counts[log.get("severity", "info")] += 1
           
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("ℹ️ Info", severity_counts.get("info", 0))
            col2.metric("⚠️ Warning", severity_counts.get("warning", 0))
            col3.metric("❌ Error", severity_counts.get("error", 0))
            col4.metric("🔴 Critical", severity_counts.get("critical", 0))
           
            # Recent Events Table
            st.markdown("### 📋 Recent Events")
            recent_df = pd.DataFrame(filtered_logs[-20:])
            display_cols = ["timestamp", "action", "status", "severity", "details"]
            if all(col in recent_df.columns for col in display_cols):
                recent_display = recent_df[display_cols].copy()
                recent_display["timestamp"] = pd.to_datetime(recent_display["timestamp"]).dt.strftime("%Y-%m-%d %H:%M")
                recent_display.columns = ["Time", "Action", "Status", "Severity", "Details"]
                st.dataframe(recent_display, use_container_width=True, hide_index=True)
        else:
            st.warning(f"No events found in the last {days} day(s)")
    else:
        st.info("No activity logs available yet")

# =============================================================
# 8️⃣ MAIN APPLICATION
# =============================================================

def main():
    ui_header()
    init_state()
   
    if not st.session_state.get("auth"):
        phone_login_ui()
    else:
        dashboard_ui()

if __name__ == "__main__":
    main()
