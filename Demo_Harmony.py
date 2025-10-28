# === ⚡ Flashmind Analyzer (Privacy-Safe Lock System) ===
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
    try:
        res = requests.get("https://api.ipify.org?format=json", timeout=5)
        return res.json().get("ip", "unknown")
    except Exception:
        return "unknown"

def mask_ip(ip):
    """Create consistent anonymous ID for user from IP."""
    return hashlib.sha256(ip.encode()).hexdigest()[:10] if ip != "unknown" else "anonymous"

def load_lock_data():
    """Load lock data, auto-upgrade old format (with IP keys) to user_id format."""
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

        # Auto-upgrade legacy IP-based format
        fixed = {}
        for key, value in data.items():
            if isinstance(value, str):
                uid = mask_ip(key)
                fixed[uid] = {"timestamp": value}
            elif isinstance(value, dict):
                uid = value.get("user_id", key)
                ts = value.get("timestamp", datetime.utcnow().isoformat())
                fixed[uid] = {"timestamp": ts}
        return fixed
    except Exception:
        return {}

def save_lock_data(data):
    """Save lock.json (only user_id entries)."""
    clean_data = {uid: {"timestamp": v.get("timestamp")} for uid, v in data.items()}
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    payload = {"files": {"lock.json": {"content": json.dumps(clean_data, indent=4)}}}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception:
        return False

def is_user_locked(user_id, data):
    """Check if user_id is locked."""
    if user_id not in data:
        return False
    try:
        ts = datetime.fromisoformat(data[user_id]["timestamp"])
        return datetime.now() - ts < timedelta(days=LOCK_DURATION_DAYS)
    except Exception:
        return False

def register_user_lock(user_id, data):
    """Lock user by user_id."""
    data[user_id] = {"timestamp": datetime.utcnow().isoformat()}
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
locked = is_user_locked(user_id, lock_data)

# ============================================================
# 🔑 Admin Access Panel
# ============================================================
with st.sidebar.expander("🔐 Admin Access", expanded=False):
    password = st.text_input("Enter Admin Password", type="password")

    if password == ADMIN_PASSWORD:
        st.success("✅ Admin Access Granted")

        if not lock_data:
            st.info("No locked users.")
        else:
            st.markdown("### 📜 Current Locked Users")
            for uid, entry in lock_data.items():
                ts = entry.get("timestamp", "")
                try:
                    dt = datetime.fromisoformat(ts)
                    date_str = dt.strftime("%Y-%m-%d")
                    time_str = dt.strftime("%H:%M:%S")
                    days_ago = (datetime.now() - dt).days
                except Exception:
                    date_str, time_str, days_ago = ts, "", "?"
                st.write(f"- 🧠 **User ID:** `{uid}` | 📅 **Date:** {date_str} | 🕒 **Time:** {time_str} | ⏱️ {days_ago} days ago")

        st.markdown("---")
        unlock_key = st.text_input("Enter User ID to Unlock")

        if st.button("🔓 Unlock User"):
            if unlock_key in lock_data:
                del lock_data[unlock_key]
                save_lock_data(lock_data)
                st.success(f"✅ Unlocked `{unlock_key}` successfully.")
            else:
                st.warning("No matching User ID found.")

        if st.button("🧹 Clear All Locks"):
            save_lock_data({})
            st.success("✅ All locks cleared (previous IP-based logs also wiped).")

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
        st.success("✅ Analysis complete. Demo valid for one use per User ID.")
        register_user_lock(user_id, lock_data)
