"""
SOC-SIEM Banking System – Streamlit Application
Full demo with authentication, MFA, forensics, SIEM reports, and Supabase backend
"""

import base64
import hashlib
import json
import random
import time
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st
from supabase import create_client, Client

# =========================================================
# Streamlit Cloud quick setup:
# 1) Add secrets under “App → Settings → Secrets”:
#       SUPABASE_URL = "https://<your-project>.supabase.co"
#       SUPABASE_KEY = "<your-anon-key>"
# 2) requirements.txt:
#       streamlit
#       supabase
#       plotly
#       pandas
# =========================================================


# =========================================================
# SECURITY MECHANISMS (6+)
# 1) Password hashing (SHA-256)
# 2) OTP MFA (time-limited codes)
# 3) Transaction encryption (simulated AES-256/base64)
# 4) Tamper-evident log hashes
# 5) Role-based access (admin/user)
# 6) SIEM-style risk scoring
# =========================================================


# -------------------------
# Supabase Initialization
# -------------------------
@st.cache_resource
def init_supabase() -> Client:
    url = st.secrets.get("SUPABASE_URL", "")
    key = st.secrets.get("SUPABASE_KEY", "")
    if not url or not key:
        st.error("⚠️ Supabase credentials missing in .secrets.toml")
        st.stop()
    return create_client(url, key)

supabase: Client = init_supabase()


# -------------------------
# Utility Functions
# -------------------------
def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_otp(length: int = 4) -> str:
    return ''.join(str(random.randint(0, 9)) for _ in range(length))

def encrypt_data(data: dict) -> str:
    """Simulated AES-256 encryption"""
    s = json.dumps(data)
    return base64.b64encode(s.encode()).decode()

def create_hash(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

def fmt_money(n: float) -> str:
    return f"${n:,.2f}"


# -------------------------
# Database Helpers
# -------------------------
def create_customer(username, password, email, balance=50000.0, role="user"):
    try:
        r = supabase.table("customers").insert({
            "username": username,
            "password_hash": hash_password(password),
            "email": email,
            "account_balance": balance,
            "mfa_enabled": True,
            "is_active": True,
            "role": role
        }).execute()
        return (True, r.data[0]) if r.data else (False, "Insert returned no data")
    except Exception as e:
        return (False, f"{e}")

def get_user_by_username(username):
    try:
        r = supabase.table("customers").select("*").eq("username", username).limit(1).execute()
        return r.data[0] if r.data else None
    except Exception:
        return None

def verify_login(username, password):
    try:
        r = supabase.table("customers").select("*").eq("username", username)\
            .eq("password_hash", hash_password(password)).limit(1).execute()
        return r.data[0] if r.data else None
    except Exception:
        return None

def create_mfa_code(cust_id):
    try:
        otp = generate_otp()
        exp = (datetime.utcnow() + timedelta(minutes=5)).isoformat() + "Z"
        supabase.table("mfa_codes").insert({
            "cust_id": cust_id, "otp_code": otp,
            "expires_at": exp, "is_used": False
        }).execute()
        return otp
    except Exception:
        return None

def verify_otp(cust_id, otp_code):
    try:
        r = supabase.table("mfa_codes").select("*")\
            .eq("cust_id", cust_id).eq("otp_code", otp_code).eq("is_used", False).execute()
        if not r.data:
            return False
        rec = r.data[0]
        if rec.get("expires_at") and datetime.fromisoformat(rec["expires_at"].replace("Z", "")) < datetime.utcnow():
            return False
        supabase.table("mfa_codes").update({
            "is_used": True, "verified_at": now_iso()
        }).eq("mfa_id", rec["mfa_id"]).execute()
        return True
    except Exception:
        return False

def log_generic(cust_id, action, status, details=""):
    try:
        payload = {"cust_id": cust_id, "action": action, "status": status, "details": details, "timestamp": now_iso()}
        supabase.table("activity_logs").insert({
            **payload, "log_hash": create_hash(payload)
        }).execute()
    except Exception:
        pass

def get_activity_logs(cust_id, limit=50):
    try:
        r = supabase.table("activity_logs").select("*").eq("cust_id", cust_id)\
            .order("created_at", desc=True).limit(limit).execute()
        return r.data or []
    except Exception:
        return []

def create_transaction(from_id, to_acc, amt):
    try:
        bal = supabase.table("customers").select("account_balance").eq("cust_id", from_id).limit(1).execute()
        if not bal.data:
            return False, "Customer not found"
        cur = float(bal.data[0]["account_balance"] or 0.0)
        if cur < amt:
            return False, "Insufficient balance"

        txn = {"from": from_id, "to": to_acc, "amount": amt, "timestamp": now_iso()}
        supabase.table("transactions").insert({
            "from_cust_id": from_id, "to_account": to_acc, "amount": amt,
            "txn_type": "TRANSFER", "encrypted_data": encrypt_data(txn),
            "txn_hash": create_hash(txn), "status": "COMPLETED"
        }).execute()
        supabase.table("customers").update({"account_balance": cur - amt}).eq("cust_id", from_id).execute()
        log_generic(from_id, "Transaction", "success", f"Transfer {fmt_money(amt)} → {to_acc}")
        return True, create_hash(txn)
    except Exception as e:
        return False, str(e)


# -------------------------
# Forensics
# -------------------------
def run_memory_forensics(cust_id):
    procs = [
        {"name": "banking-app.exe", "pid": 1234, "cpu": 2.3, "memory": 45.2, "status": "safe"},
        {"name": "svchost.exe", "pid": 9012, "cpu": 1.2, "memory": 23.4, "status": "safe"},
        {"name": "chrome.exe", "pid": 3456, "cpu": 15.4, "memory": 234.5, "status": "safe"},
        {"name": "suspicious.exe", "pid": 7890, "cpu": 45.2, "memory": 567.8, "status": "suspicious"},
    ]
    susp = sum(p["status"] == "suspicious" for p in procs)
    supabase.table("forensic_memory_scans").insert({
        "cust_id": cust_id, "total_processes": len(procs),
        "suspicious_processes": susp, "scan_data": {"processes": procs}
    }).execute()
    log_generic(cust_id, "Memory Forensics", "success", f"{susp} suspicious")
    return procs, susp

def run_network_forensics(cust_id):
    pkts = [
        {"src": "192.168.1.10", "dst": "8.8.8.8", "protocol": "DNS", "encrypted": False, "size": 64},
        {"src": "192.168.1.10", "dst": "10.0.0.50", "protocol": "HTTPS", "encrypted": True, "size": 1024},
    ]
    enc = sum(p["encrypted"] for p in pkts)
    supabase.table("forensic_network_captures").insert({
        "cust_id": cust_id, "total_packets": len(pkts),
        "encrypted_packets": enc, "unencrypted_packets": len(pkts) - enc,
        "capture_data": {"packets": pkts}
    }).execute()
    log_generic(cust_id, "Network Forensics", "success", f"{enc} encrypted")
    return pkts, enc, len(pkts) - enc

def run_stego_scan(cust_id, fname):
    analysis = {"lsb": random.random() > 0.7, "dct": random.random() > 0.8, "chi_square": random.random() * 100}
    score = (30 if analysis["lsb"] else 0) + (40 if analysis["dct"] else 0) + (30 if analysis["chi_square"] > 50 else 0)
    supabase.table("forensic_steganography_scans").insert({
        "cust_id": cust_id, "file_name": fname, "suspicion_score": score, "analysis_data": analysis
    }).execute()
    log_generic(cust_id, "Stego Scan", "warning" if score > 50 else "success", f"{fname} {score}%")
    return analysis, score


# -------------------------
# SIEM Risk Score
# -------------------------
def calc_risk(cust_id):
    logs = get_activity_logs(cust_id, 100)
    failed = sum(l["action"] == "Login Attempt" and l["status"] != "success" for l in logs)
    warn = sum(l["status"] == "warning" for l in logs)
    return min(failed * 10 + warn * 15, 100)


# -------------------------
# Streamlit UI
# -------------------------
def init_session():
    for k, v in {"authenticated": False, "mfa_verified": False, "user": None, "otp": None, "role": "user"}.items():
        st.session_state.setdefault(k, v)

def header():
    st.set_page_config(page_title="SOC-SIEM Banking", page_icon="🏦", layout="wide")
    st.markdown(
        "<div style='background:linear-gradient(90deg,#1e3a8a,#7c3aed);padding:16px;border-radius:12px;margin-bottom:16px'>"
        "<h2 style='color:white;margin:0'>🛡️ SOC-SIEM Banking System</h2>"
        "<p style='color:white;margin:0'>Advanced Security Operations & Forensic Banking App</p></div>",
        unsafe_allow_html=True
    )


# --- Auth Pages ---
def show_login():
    st.subheader("🔐 Secure Login")
    c1, c2 = st.columns(2)
    with c1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login with MFA"):
            user = verify_login(u, p)
            if user:
                otp = create_mfa_code(user["cust_id"])
                st.session_state.update({"authenticated": True, "user": user, "otp": otp, "role": user.get("role", "user")})
                log_generic(user["cust_id"], "Login Attempt", "success", f"user={u}")
                st.success(f"OTP: **{otp}** (demo)")
                st.rerun()
            else:
                st.error("Invalid credentials")
    with c2:
        st.write("### Create Account")
        nu = st.text_input("New Username")
        ne = st.text_input("Email")
        np = st.text_input("New Password", type="password")
        if st.button("Create Account"):
            ok, msg = create_customer(nu, np, ne)
            st.success("Account created" if ok else f"Failed: {msg}")

def show_mfa():
    st.subheader("🔒 MFA Verification")
    otp = st.text_input("Enter OTP")
    if st.button("Verify"):
        if verify_otp(st.session_state.user["cust_id"], otp):
            st.session_state.mfa_verified = True
            log_generic(st.session_state.user["cust_id"], "MFA", "success", "verified")
            st.rerun()
        else:
            st.error("Invalid OTP")
    if st.button("Back"):
        st.session_state.authenticated = False
        st.session_state.user = None
        st.rerun()


# --- Dashboard / Modules ---
def dash(user):
    st.subheader("🏠 Dashboard")
    risk = calc_risk(user["cust_id"])
    logs = get_activity_logs(user["cust_id"], 100)
    txns = sum(l["action"] == "Transaction" for l in logs)
    fails = sum(l["action"] == "Login Attempt" and l["status"] != "success" for l in logs)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk", f"{risk}%")
    c2.metric("Transactions", txns)
    c3.metric("Failed Logins", fails)
    c4.metric("MFA", "✅" if user.get("mfa_enabled") else "❌")
    st.markdown("---")
    st.dataframe(pd.DataFrame(logs) if logs else pd.DataFrame([{"info": "no logs"}]))


def transactions(user):
    st.subheader("💳 Transactions")
    to = st.text_input("Recipient")
    amt = st.number_input("Amount", min_value=0.01, step=0.01)
    if st.button("Send"):
        ok, msg = create_transaction(user["cust_id"], to, amt)
        st.success("Success" if ok else f"Failed: {msg}")
        st.rerun()


def forensics(user):
    st.subheader("🔬 Forensics")
    if st.button("Run Memory Scan"):
        data, s = run_memory_forensics(user["cust_id"])
        st.write(f"{s} suspicious")
        st.dataframe(pd.DataFrame(data))
    if st.button("Run Network Scan"):
        pk, e, u = run_network_forensics(user["cust_id"])
        st.write(f"{e} encrypted / {u} unencrypted")
    f = st.file_uploader("Image for Stego")
    if f and st.button("Analyze"):
        a, sc = run_stego_scan(user["cust_id"], f.name)
        st.metric("Suspicion", f"{sc}%")


def siem(user):
    st.subheader("📊 SIEM Reports")
    logs = get_activity_logs(user["cust_id"], 200)
    if not logs:
        st.info("No logs")
        return
    dist = {}
    for l in logs:
        dist[l["action"]] = dist.get(l["action"], 0) + 1
    st.plotly_chart(px.pie(values=list(dist.values()), names=list(dist.keys())))
    if st.button("Export Report"):
        rep = {"user": user["username"], "generated_at": now_iso(), "events": logs}
        st.download_button("Download", json.dumps(rep, indent=2).encode(), "report.json", "application/json")


# --- Main ---
def main():
    header()
    init_session()

    if not st.session_state.authenticated:
        show_login()
        return
    if not st.session_state.mfa_verified:
        show_mfa()
        return

    user = st.session_state.user
    with st.sidebar:
        st.markdown(f"👤 **{user['username']}**  Balance: {fmt_money(user.get('account_balance',0))}")
        page = st.radio("Navigate", ["Dashboard", "Transactions", "Forensics", "SIEM"])
        if st.button("Logout"):
            for k in ["authenticated", "mfa_verified", "user", "otp"]:
                st.session_state.pop(k, None)
            st.rerun()

    if page == "Dashboard":
        dash(user)
    elif page == "Transactions":
        transactions(user)
    elif page == "Forensics":
        forensics(user)
    elif page == "SIEM":
        siem(user)


if __name__ == "__main__":
    main()
