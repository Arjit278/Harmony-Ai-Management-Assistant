# === ⚡ Flashmind Analyzer (Enhanced Lock System) ===
# Author: Arjit | Flashmind Systems © 2025

import streamlit as st
import requests
import json
import hashlib
from datetime import datetime, timedelta

# ============================================================
# 🔐 Configuration
# ============================================================
ENGINE_KEY = st.secrets.get("FLASHMIND_KEY", None)
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY", None)
LOCK_FILE_URL = "https://api.github.com/gists/7cd8a2b265c34b1592e88d1d5b863a8a"
ADMIN_PASSWORD = "Harmony_Chand@9028"
LOCK_DURATION_DAYS = 30

# ============================================================
# ⚙️ Utilities
# ============================================================
def get_user_ip():
    """Fetch the user’s public IP address."""
    try:
        res = requests.get("https://api.ipify.org?format=json", timeout=5)
        return res.json().get("ip", "unknown")
    except Exception:
        return "unknown"

def mask_ip(ip):
    """Generate a masked user ID from IP address."""
    return hashlib.sha256(ip.encode()).hexdigest()[:10] if ip != "unknown" else "anonymous-user"

def load_lock_data():
    """Load lock.json and auto-upgrade any old entries."""
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"}
        gist = requests.get(LOCK_FILE_URL, headers=headers, timeout=10).json()
        files = gist.get("files", {})
        content = "{}"
        if "lock.json" in files:
            content = files["lock.json"]["content"]
        elif files:
            content = next(iter(files.values()))["content"]
        data = json.loads(content)

        fixed = {}
        for ip, value in data.items():
            if isinstance(value, str):  # old style (timestamp only)
                fixed[ip] = {
                    "user_id": mask_ip(ip),
                    "timestamp": value
                }
            else:
                fixed[ip] = value
        return fixed
    except Exception:
        return {}

def save_lock_data(data):
    """Save updated lock data to GitHub Gist."""
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    payload = {"files": {"lock.json": {"content": json.dumps(data, indent=4)}}}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception:
        return False

def is_user_locked(ip, data):
    """Check whether a user’s IP is within the lock period."""
    if ip not in data:
        return False
    try:
        ts = datetime.fromisoformat(data[ip]["timestamp"])
        return datetime.now() - ts < timedelta(days=LOCK_DURATION_DAYS)
    except Exception:
        return False

def register_user_lock(ip, data):
    """Register (or update) a user’s lock."""
    data[ip] = {
        "user_id": mask_ip(ip),
        "timestamp": datetime.utcnow().isoformat()
    }
    save_lock_data(data)

# ============================================================
# 🚀 Streamlit UI
# ============================================================
st.set_page_config(page_title="⚡ Flashmind Analyzer", page_icon="⚡")
st.title("⚡ Flashmind Analyzer")

if LOCK_API_KEY:
    st.caption("✅ Connected with Flashmind API")
else:
    st.caption("❌ Missing LOCK_API_KEY – please add in Streamlit Secrets")

st.caption("Enjoy your trial — one use per user | © 2025 Flashmind Systems")

ip = get_user_ip()
user_id = mask_ip(ip)
st.write(f"🔒 User ID: `{user_id}`")

lock_data = load_lock_data()
locked = is_user_locked(ip, lock_data)

# ============================================================
# 🔑 Admin Access Panel
# ============================================================
with st.sidebar.expander("🔐 Admin Access", expanded=False):
    password = st.text_input("Enter Admin Password", type="password")

    if password == ADMIN_PASSWORD:
        st.success("✅ Admin Access Granted")

        # Reload latest lock file each time admin opens panel
        lock_data = load_lock_data()

        if not lock_data:
            st.info("No locked users.")
        else:
            st.markdown("### 📜 Current Locked Users")
            for ip_addr, entry in lock_data.items():
                user = entry.get("user_id", "unknown")
                ts = entry.get("timestamp", "")
                try:
                    dt = datetime.fromisoformat(ts)
                    date_str = dt.strftime("%Y-%m-%d")
                    time_str = dt.strftime("%H:%M:%S")
                    days_ago = (datetime.now() - dt).days
                except Exception:
                    date_str, time_str, days_ago = ts, "", ""
                st.write(
                    f"- 🧠 **User ID:** `{user}` | 🌐 **IP:** {ip_addr} | 📅 **Date:** {date_str} | 🕒 **Time:** {time_str} | ⏱️ **{days_ago} days ago**"
                )

        st.markdown("---")
        unlock_key = st.text_input("Enter IP or User ID to Unlock")

        if st.button("🔓 Unlock User"):
            found = False
            for ip_addr, entry in list(lock_data.items()):
                if unlock_key == ip_addr or unlock_key == entry.get("user_id"):
                    del lock_data[ip_addr]
                    save_lock_data(lock_data)
                    st.success(f"✅ Unlocked `{unlock_key}` successfully.")
                    st.rerun()  # 👈 instant reload for both user & admin
                    found = True
                    break
            if not found:
                st.warning("No matching IP or User ID found.")

        if st.button("🧹 Clear All Locks"):
            save_lock_data({})
            st.success("✅ All locks cleared.")
            st.rerun()

# ============================================================
# 🧩 User Lock Check
# ============================================================
if locked:
    st.error("⚠ You have already used this demo in the past 30 days.\nPlease contact admin for enterprise access.")
    st.stop()

# ============================================================
# 📝 Pre-Access Form
# ============================================================
st.markdown("### 📝 Step 1: Complete Access Form")
st.markdown("""
Please fill this quick form before proceeding:  
👉 [Open the Access Form](https://41dt5g.share-na2.hsforms.com/2K9_0lqxDTzeMPY4ZyJkBLQ)

Then check below to continue.
""")

form_done = st.checkbox("✅ I have filled and submitted the access form")

if not form_done:
    st.warning("Please confirm the form submission before proceeding.")
    st.stop()

# ============================================================
# ⚡ Flashmind Analysis
# ============================================================
topic = st.text_input("📘 Enter Analysis Topic")

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic.")
    else:
        st.info(f"Analyzing **{topic}**...")
        st.success("✅ Analysis complete. Demo valid for one use per IP/User.")
        register_user_lock(ip, lock_data)
