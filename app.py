"""
Enhanced SOC-SIEM Banking System
Streamlit + Supabase + Twilio + Advanced Forensics + SIEM Dashboard

Key Improvements:
  ✅ Enhanced OTP security with rate limiting
  ✅ Improved transaction validation and audit trails
  ✅ More accurate forensic analysis algorithms
  ✅ Advanced SIEM analytics with threat detection
  ✅ Better error handling and logging
  ✅ Enhanced steganography detection using LSB analysis
  ✅ Real-time anomaly detection
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
# 5️⃣ FORENSICS MODULES
# =============================================================

def run_memory_forensics(cust_id: int) -> Tuple[List[dict], int, dict]:
    """Real-time memory forensics using psutil to analyze actual system processes."""
    try:
        import psutil
        
        all_processes = []
        suspicious_count = 0
        malicious_count = 0
        
        # Known suspicious patterns
        suspicious_names = ["mimikatz", "keylog", "inject", "dump", "crack", "backdoor", "trojan", "rootkit"]
        high_risk_ports = [4444, 5555, 6666, 31337]  # Common hacker ports
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info', 'connections', 'exe']):
            try:
                proc_info = proc.info
                
                # Get process details
                pid = proc_info.get('pid', 0)
                name = proc_info.get('name', 'Unknown')
                username = proc_info.get('username', 'UNKNOWN')
                
                # Get CPU and memory
                try:
                    cpu = proc.cpu_percent(interval=0.1)
                except:
                    cpu = 0.0
                
                mem_info = proc_info.get('memory_info')
                mem_mb = round(mem_info.rss / (1024 * 1024), 2) if mem_info else 0
                
                # Get executable path
                try:
                    exe_path = proc_info.get('exe', 'N/A')
                except:
                    exe_path = 'Access Denied'
                
                # Analyze for suspicious behavior
                status = "safe"
                reasons = []
                
                # Check 1: Suspicious process name
                name_lower = name.lower()
                if any(sus in name_lower for sus in suspicious_names):
                    status = "malicious"
                    reasons.append("Malicious process name detected")
                    malicious_count += 1
                
                # Check 2: High CPU usage (over 50%)
                elif cpu > 50:
                    status = "suspicious"
                    reasons.append(f"High CPU usage: {cpu:.1f}%")
                    suspicious_count += 1
                
                # Check 3: Excessive memory usage (over 1GB)
                elif mem_mb > 1024:
                    status = "suspicious"
                    reasons.append(f"High memory usage: {mem_mb:.0f}MB")
                    suspicious_count += 1
                
                # Check 4: Process with no username (hidden/system exploit)
                elif username == 'UNKNOWN' or username is None:
                    status = "suspicious"
                    reasons.append("Unknown user - potential privilege escalation")
                    suspicious_count += 1
                
                # Check 5: Suspicious network connections
                try:
                    connections = proc.connections(kind='inet')
                    if connections:
                        for conn in connections:
                            if hasattr(conn, 'laddr') and conn.laddr:
                                port = conn.laddr.port
                                if port in high_risk_ports:
                                    status = "malicious"
                                    reasons.append(f"Suspicious port detected: {port}")
                                    malicious_count += 1
                                    suspicious_count -= 1 if status == "suspicious" else 0
                                    break
                except:
                    pass
                
                # Check 6: Process running from suspicious location
                if exe_path and exe_path != 'Access Denied' and exe_path != 'N/A':
                    suspicious_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\', '\\downloads\\']
                    if any(sus_path in exe_path.lower() for sus_path in suspicious_paths):
                        if status == "safe":
                            status = "suspicious"
                            reasons.append("Running from suspicious location")
                            suspicious_count += 1
                
                process_data = {
                    "name": name,
                    "pid": pid,
                    "cpu": round(cpu, 2),
                    "mem": mem_mb,
                    "user": username.split('\\')[-1] if username else "UNKNOWN",
                    "status": status,
                    "path": exe_path[:50] + "..." if len(exe_path) > 50 else exe_path,
                    "reason": " | ".join(reasons) if reasons else "Normal behavior"
                }
                
                all_processes.append(process_data)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Calculate metrics
        total_mem = sum(p["mem"] for p in all_processes)
        avg_cpu = sum(p["cpu"] for p in all_processes) / len(all_processes) if all_processes else 0
        
        metrics = {
            "total_memory_mb": round(total_mem, 2),
            "avg_cpu_usage": round(avg_cpu, 2),
            "total_processes": len(all_processes),
            "suspicious_count": suspicious_count,
            "malicious_count": malicious_count
        }
        
        scan_data = {
            "processes": all_processes[:100],  # Limit to top 100 for storage
            "metrics": metrics,
            "scan_time": now_iso()
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
        
    except ImportError:
        st.error("⚠️ psutil library not installed. Using simulated data.")
        # Fallback to simulated data
        return run_memory_forensics_simulated(cust_id)
    except Exception as e:
        st.error(f"❌ Memory scan error: {e}")
        return [], 0, {}

def run_memory_forensics_simulated(cust_id: int) -> Tuple[List[dict], int, dict]:
    """Fallback simulated memory forensics if psutil is not available."""
    processes = [
        {"name": "streamlit", "pid": 1234, "cpu": 15.2, "mem": 245, "user": "USER", "status": "safe", 
         "path": "/usr/local/bin/streamlit", "reason": "Normal behavior"},
        {"name": "python", "pid": 1235, "cpu": 8.5, "mem": 180, "user": "USER", "status": "safe", 
         "path": "/usr/bin/python3", "reason": "Normal behavior"},
    ]
    
    metrics = {
        "total_memory_mb": 425,
        "avg_cpu_usage": 11.85,
        "total_processes": 2,
        "suspicious_count": 0,
        "malicious_count": 0
    }
    
    return processes, 0, metrics

def run_network_forensics(cust_id: int) -> Tuple[List[dict], dict]:
    """Real-time network forensics using scapy to capture actual network traffic."""
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
        import socket
        
        st.info("🔍 Starting packet capture for 10 seconds...")
        
        captured_packets = []
        suspicious_count = 0
        
        # Known malicious IPs and suspicious ports
        suspicious_ips = ["185.220.101", "45.142.212", "195.123."]  # Tor exit nodes, known malicious prefixes
        suspicious_ports = [4444, 5555, 6666, 7777, 31337, 12345]  # Common backdoor ports
        high_risk_protocols = ["FTP", "TELNET", "HTTP"]  # Unencrypted protocols
        
        def packet_callback(packet):
            try:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Determine protocol
                    protocol = "Unknown"
                    src_port = 0
                    dst_port = 0
                    encrypted = False
                    packet_size = len(packet)
                    
                    if TCP in packet:
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                        
                        # Identify protocol by port
                        if dst_port == 443 or src_port == 443:
                            protocol = "HTTPS"
                            encrypted = True
                        elif dst_port == 80 or src_port == 80:
                            protocol = "HTTP"
                        elif dst_port == 22 or src_port == 22:
                            protocol = "SSH"
                            encrypted = True
                        elif dst_port == 21 or src_port == 21:
                            protocol = "FTP"
                        elif dst_port == 23 or src_port == 23:
                            protocol = "TELNET"
                        elif dst_port == 3389 or src_port == 3389:
                            protocol = "RDP"
                            encrypted = True
                        elif dst_port == 25 or src_port == 25:
                            protocol = "SMTP"
                        else:
                            protocol = "TCP"
                    
                    elif UDP in packet:
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                        
                        if dst_port == 53 or src_port == 53:
                            protocol = "DNS"
                        elif dst_port == 123 or src_port == 123:
                            protocol = "NTP"
                        else:
                            protocol = "UDP"
                    
                    elif ICMP in packet:
                        protocol = "ICMP"
                    
                    # Analyze for suspicious activity
                    status = "safe"
                    reasons = []
                    
                    # Check 1: Suspicious destination IP
                    if any(suspicious_ip in dst_ip for suspicious_ip in suspicious_ips):
                        status = "suspicious"
                        reasons.append(f"Connection to suspicious IP: {dst_ip}")
                    
                    # Check 2: Suspicious ports
                    if dst_port in suspicious_ports or src_port in suspicious_ports:
                        status = "suspicious"
                        reasons.append(f"Suspicious port detected: {dst_port if dst_port in suspicious_ports else src_port}")
                    
                    # Check 3: Unencrypted sensitive protocols
                    if protocol in high_risk_protocols:
                        status = "suspicious"
                        reasons.append(f"Unencrypted {protocol} traffic detected")
                    
                    # Check 4: Large unencrypted data transfer
                    if packet_size > 1000 and not encrypted:
                        status = "suspicious"
                        reasons.append(f"Large unencrypted transfer: {packet_size} bytes")
                    
                    # Check 5: DNS tunneling detection (unusually large DNS packets)
                    if protocol == "DNS" and packet_size > 512:
                        status = "suspicious"
                        reasons.append("Potential DNS tunneling (large DNS packet)")
                    
                    packet_info = {
                        "src": src_ip,
                        "dst": dst_ip,
                        "proto": protocol,
                        "port": dst_port if dst_port else src_port,
                        "encrypted": encrypted,
                        "size": packet_size,
                        "status": status,
                        "reason": " | ".join(reasons) if reasons else "Normal traffic"
                    }
                    
                    captured_packets.append(packet_info)
                    
                    if len(captured_packets) >= 50:  # Limit to 50 packets
                        return True  # Stop sniffing
                        
            except Exception as e:
                pass
        
        # Capture packets for 10 seconds or until 50 packets are captured
        try:
            sniff(prn=packet_callback, timeout=10, store=False)
        except PermissionError:
            st.warning("⚠️ Insufficient permissions for packet capture. Please run with appropriate privileges.")
            return run_network_forensics_simulated(cust_id)
        
        if not captured_packets:
            st.warning("⚠️ No packets captured. Using simulated data.")
            return run_network_forensics_simulated(cust_id)
        
        # Calculate metrics
        encrypted_count = sum(1 for p in captured_packets if p["encrypted"])
        unencrypted_count = len(captured_packets) - encrypted_count
        suspicious_count = sum(1 for p in captured_packets if p["status"] == "suspicious")
        total_bytes = sum(p["size"] for p in captured_packets)
        
        # Protocol distribution
        proto_dist = defaultdict(int)
        for p in captured_packets:
            proto_dist[p["proto"]] += 1
        
        metrics = {
            "total_packets": len(captured_packets),
            "encrypted_packets": encrypted_count,
            "unencrypted_packets": unencrypted_count,
            "suspicious_packets": suspicious_count,
            "total_bytes": total_bytes,
            "protocol_distribution": dict(proto_dist)
        }
        
        capture_data = {
            "packets": captured_packets,
            "metrics": metrics,
            "capture_time": now_iso()
        }
        
        safe_insert("forensic_network_captures", {
            "cust_id": cust_id,
            "total_packets": len(captured_packets),
            "encrypted_packets": encrypted_count,
            "unencrypted_packets": unencrypted_count,
            "suspicious_packets": suspicious_count,
            "capture_data": capture_data,
            "capture_timestamp": now_iso()
        })
        
        severity = "warning" if suspicious_count > 0 else "info"
        log_event(cust_id, "Network Forensics", "completed", 
                 f"Analyzed {len(captured_packets)} packets: {encrypted_count} encrypted, {suspicious_count} suspicious", 
                 severity=severity)
        
        return captured_packets, metrics
        
    except ImportError:
        st.warning("⚠️ Scapy library not installed. Using simulated data.")
        return run_network_forensics_simulated(cust_id)
    except Exception as e:
        st.error(f"❌ Network capture error: {e}")
        return run_network_forensics_simulated(cust_id)

def run_network_forensics_simulated(cust_id: int) -> Tuple[List[dict], dict]:
    """Fallback simulated network forensics if scapy is not available or permissions are insufficient."""
    try:
        import socket
        import psutil
        
        # Get actual network connections from current process
        captured_packets = []
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Determine protocol
                    protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    
                    # Try to resolve local IP
                    try:
                        local_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
                        remote_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
                        remote_port = conn.raddr.port if conn.raddr else 0
                    except:
                        continue
                    
                    # Identify common protocols by port
                    encrypted = False
                    if remote_port == 443:
                        protocol = "HTTPS"
                        encrypted = True
                    elif remote_port == 80:
                        protocol = "HTTP"
                    elif remote_port == 22:
                        protocol = "SSH"
                        encrypted = True
                    elif remote_port == 53:
                        protocol = "DNS"
                    
                    packet_info = {
                        "src": local_ip,
                        "dst": remote_ip,
                        "proto": protocol,
                        "port": remote_port,
                        "encrypted": encrypted,
                        "size": 1420 if encrypted else 512,
                        "status": "safe",
                        "reason": "Active connection"
                    }
                    
                    captured_packets.append(packet_info)
                    
                    if len(captured_packets) >= 20:
                        break
            except:
                continue
        
        if not captured_packets:
            # Absolute fallback to basic simulated data
            captured_packets = [
                {"src": "127.0.0.1", "dst": "8.8.8.8", "proto": "DNS", "port": 53, "encrypted": False, 
                 "size": 64, "status": "safe", "reason": "DNS query"},
                {"src": "127.0.0.1", "dst": "172.217.0.46", "proto": "HTTPS", "port": 443, "encrypted": True, 
                 "size": 1420, "status": "safe", "reason": "Secure web traffic"},
            ]
        
        encrypted_count = sum(1 for p in captured_packets if p["encrypted"])
        unencrypted_count = len(captured_packets) - encrypted_count
        suspicious_count = sum(1 for p in captured_packets if p["status"] == "suspicious")
        total_bytes = sum(p["size"] for p in captured_packets)
        
        proto_dist = defaultdict(int)
        for p in captured_packets:
            proto_dist[p["proto"]] += 1
        
        metrics = {
            "total_packets": len(captured_packets),
            "encrypted_packets": encrypted_count,
            "unencrypted_packets": unencrypted_count,
            "suspicious_packets": suspicious_count,
            "total_bytes": total_bytes,
            "protocol_distribution": dict(proto_dist)
        }
        
        return captured_packets, metrics
        
    except Exception as e:
        # Last resort fallback
        packets = [
            {"src": "127.0.0.1", "dst": "8.8.8.8", "proto": "DNS", "port": 53, "encrypted": False, 
             "size": 64, "status": "safe", "reason": "DNS query"}
        ]
        metrics = {
            "total_packets": 1,
            "encrypted_packets": 0,
            "unencrypted_packets": 1,
            "suspicious_packets": 0,
            "total_bytes": 64,
            "protocol_distribution": {"DNS": 1}
        }
        return packets, metrics

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
        "🛡️ SOC-SIEM Banking System</h2>",
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
    
    tab1, tab2, tab3 = st.tabs(["🧠 Memory Forensics", "🌐 Network Forensics", "🖼️ Steganography"])
    
    with tab1:
        st.markdown("### Memory Forensics Scanner")
        st.info("Scans for suspicious processes and memory anomalies")
        
        if st.button("🔍 Run Memory Scan", use_container_width=True):
            with st.spinner("Scanning memory processes..."):
                processes, suspicious_count, metrics = run_memory_forensics(cid)
                time.sleep(1)
            
            if suspicious_count > 0:
                st.warning(f"⚠️ Found {suspicious_count} suspicious process(es)!")
            else:
                st.success("✅ No suspicious processes detected")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Processes", metrics["total_processes"])
            col2.metric("Total Memory (MB)", metrics["total_memory_mb"])
            col3.metric("Avg CPU %", f"{metrics['avg_cpu_usage']}%")
            
            st.markdown("#### Process Details")
            proc_df = pd.DataFrame(processes)
            st.dataframe(proc_df, use_container_width=True, hide_index=True)
    
    with tab2:
        st.markdown("### Network Traffic Analyzer")
        st.info("Captures and analyzes network packets for anomalies")
        
        if st.button("📡 Capture Network Traffic", use_container_width=True):
            with st.spinner("Capturing network packets..."):
                packets, metrics = run_network_forensics(cid)
                time.sleep(1)
            
            if metrics["suspicious_packets"] > 0:
                st.warning(f"⚠️ Found {metrics['suspicious_packets']} suspicious packet(s)!")
            else:
                st.success("✅ No suspicious network activity detected")
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Packets", metrics["total_packets"])
            col2.metric("🔒 Encrypted", metrics["encrypted_packets"])
            col3.metric("🔓 Unencrypted", metrics["unencrypted_packets"])
            col4.metric("⚠️ Suspicious", metrics["suspicious_packets"])
            
            st.markdown("#### Protocol Distribution")
            proto_df = pd.DataFrame(list(metrics["protocol_distribution"].items()), columns=["Protocol", "Count"])
            fig = px.pie(proto_df, values="Count", names="Protocol", title="Network Protocols")
            st.plotly_chart(fig, use_container_width=True)
            
            st.markdown("#### Packet Details")
            pkt_df = pd.DataFrame(packets)
            st.dataframe(pkt_df, use_container_width=True, hide_index=True)
    
    with tab3:
        st.markdown("### Steganography Detection")
        st.info("Analyzes images for hidden data using LSB analysis and statistical methods")
        
        uploaded = st.file_uploader("Upload Image (JPG, PNG)", type=["jpg", "jpeg", "png"])
        
        if uploaded:
            if st.button("🔍 Analyze Image", use_container_width=True):
                with st.spinner("Performing deep image analysis..."):
                    analysis, score, img, edges, lsb = run_steganography_analysis(cid, uploaded)
                    time.sleep(1)
                
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
