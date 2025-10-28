# === ⚡ Flashmind Analyzer (Privacy-Safe + Flashmind Engine) ===
# Author: Arjit | Flashmind Systems © 2025
#
# NOTE: Add your secrets in Streamlit "Secrets" (recommended):
#   [secrets]
#   FLASHMIND_KEY = "your_engine_key"
#   LOCK_API_KEY = "your_github_token_with_gist_scope"
#   ADMIN_PASSWORD = "your_admin_password"
#   # or, if you prefer encoded:
#   ADMIN_PASSWORD_BASE64 = "YmFzZTY0X2V4YW1wbGVfcGFzc3dvcmQ="

import streamlit as st
import requests
import json
import hashlib
import base64
from datetime import datetime, timedelta

# ============================================================
# 🔐 Configuration (load from Streamlit Secrets)
# ============================================================
ENGINE_KEY = st.secrets.get("FLASHMIND_KEY", None)
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY", None)
LOCK_FILE_URL = "https://api.github.com/gists/7cd8a2b265c34b1592e88d1d5b863a8a"
LOCK_DURATION_DAYS = 30

# Admin password: prefer plain secret, fallback to base64-decoded secret
_ADMIN_PLAIN = st.secrets.get("ADMIN_PASSWORD", None)
_ADMIN_B64 = st.secrets.get("ADMIN_PASSWORD_BASE64", None)
if not _ADMIN_PLAIN and _ADMIN_B64:
    try:
        _ADMIN_PLAIN = base64.b64decode(_ADMIN_B64).decode("utf-8")
    except Exception:
        _ADMIN_PLAIN = None
ADMIN_PASSWORD = _ADMIN_PLAIN  # will be None if not provided

# ============================================================
# ⚙️ Utilities
# ============================================================
def get_user_ip():
    """Fetch the user's public IP address (used only locally to create a stable user_id)."""
    try:
        res = requests.get("https://api.ipify.org?format=json", timeout=5)
        return res.json().get("ip", "unknown")
    except Exception:
        return "unknown"

def mask_ip(ip):
    """Create consistent anonymous user ID from IP (deterministic)."""
    return hashlib.sha256(ip.encode()).hexdigest()[:10] if ip != "unknown" else "anonymous"

def save_lock_data(data):
    """Write a cleaned user_id-only lock.json to the configured Gist."""
    clean_data = {uid: {"timestamp": v.get("timestamp")} for uid, v in data.items()}
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    payload = {"files": {"lock.json": {"content": json.dumps(clean_data, indent=4)}}}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception:
        return False

def load_lock_data():
    """Load lock data from the Gist, auto-migrate old IP-keyed entries to user_id keys,
       overwrite the Gist to keep only user_id entries (privacy-safe)."""
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
        for key, value in data.items():
            # legacy format: "ip": "timestamp"
            if isinstance(value, str):
                uid = mask_ip(key)
                fixed[uid] = {"timestamp": value}
            # possibly older dicts that included ip keys or user_id
            elif isinstance(value, dict):
                # if it already contains 'user_id' use that, else key is maybe user_id already
                if "user_id" in value:
                    uid = value["user_id"]
                else:
                    uid = key
                ts = value.get("timestamp", datetime.utcnow().isoformat())
                fixed[uid] = {"timestamp": ts}
        # overwrite Gist with cleaned user-id-only structure
        save_lock_data(fixed)
        return fixed
    except Exception:
        return {}

def is_user_locked(user_id, data):
    """Return True if the user_id exists and is within the lock window."""
    if user_id not in data:
        return False
    try:
        ts = datetime.fromisoformat(data[user_id]["timestamp"])
        return datetime.now() - ts < timedelta(days=LOCK_DURATION_DAYS)
    except Exception:
        return False

def register_user_lock(user_id, data):
    """Register a user_id lock (timestamp now) and save to Gist."""
    data[user_id] = {"timestamp": datetime.utcnow().isoformat()}
    save_lock_data(data)

# ============================================================
# === Flashmind Core
# ============================================================
def get_references(query):
    return [
        f"https://www.brookings.edu/research/{query.replace(' ', '-')}-2025",
        f"https://www.weforum.org/agenda/{query.replace(' ', '-')}-trends",
        f"https://www.mckinsey.com/{query.replace(' ', '-')}-insights-2025"
    ]

def build_locked_prompt(topic: str):
    refs_md = "\n".join([f"- [{r}]({r})" for r in get_references(topic)])
    return f"""
Analyze topic **{topic}** (2025 Edition) using Flashmind Strategic 360.

1. Identify Root Causes (sum = 100%)
2. Recommend actionable strategies
3. Markdown table:
| Root Cause | % | Solution |
|-------------|---|----------|
| Cause 1 | 25 | Solution |
| Cause 2 | 35 | Solution |
| Cause 3 | 40 | Solution |

{refs_md}
"""

def flashmind_engine(prompt, key):
    """Call three models (as in your original) and return three text results.
       If ENGINE_KEY is not configured, return informative placeholders."""
    if not key:
        return {"Analysis 1": "❌ Key not configured.", "Analysis 2": "⚠ None.", "Summary": "⚠ None."}
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    def call(model):
        try:
            res = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json={"model": model, "messages": [{"role": "user", "content": prompt}]},
                timeout=60
            )
            data = res.json()
            return data["choices"][0]["message"]["content"].strip()
        except Exception:
            return "⚠ Engine unavailable."

    return {
        "Analysis 1": call("groq/compound-mini"),
        "Analysis 2": call("llama-3.1-8b-instant"),
        "Summary": call("groq/compound")
    }

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

# compute local user id from IP (IP not stored)
ip = get_user_ip()
user_id = mask_ip(ip)
st.write(f"🔒 User ID: `{user_id}`")

# load lock file (user-id keyed) and check lock
lock_data = load_lock_data()
locked = is_user_locked(user_id, lock_data)

# ============================================================
# 🔑 Admin Access Panel (secrets-based; disabled if no secret)
# ============================================================
from datetime import timezone, timedelta
with st.sidebar.expander("🔐 Admin Access", expanded=False):
    if ADMIN_PASSWORD is None:
        st.warning("Admin access is disabled — set ADMIN_PASSWORD (or ADMIN_PASSWORD_BASE64) in Streamlit Secrets.")
    else:
        password = st.text_input("Enter Admin Password", type="password")
        if password == ADMIN_PASSWORD:
            st.success("✅ Admin Access Granted")

            # reload latest lock file for accuracy
            lock_data = load_lock_data()

            if not lock_data:
                st.info("No locked users.")
            else:
                st.markdown("### 📜 Current Locked Users")
                for uid, entry in lock_data.items():
                    ts = entry.get("timestamp", "")
                    try:
                        IST_OFFSET = timedelta(hours=5, minutes=30)
                        dt = datetime.fromisoformat(ts)
                        local_dt = dt.replace(tzinfo=timezone.utc) + IST_OFFSET
                        date_str = local_dt.strftime("%Y-%m-%d")
                        time_str = local_dt.strftime("%H:%M:%S")
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
                    st.rerun()  # ensure app refreshes so user can access immediately
                else:
                    st.warning("No matching User ID found.")

            if st.button("🧹 Clear All Locks"):
                save_lock_data({})
                st.success("✅ All locks cleared (previous IP-based logs also wiped).")
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
import streamlit as st

st.markdown("### 📝 Step 1: Complete Access Form")
st.write("Please fill out the short access form to continue:")

# Use a styled HTML button link
st.markdown("""
    <style>
        .form-btn {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 0.6em 1.2em;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 1em;
            border-radius: 8px;
            cursor: pointer;
        }
        .form-btn:hover {
            background-color: #45a049;
        }
    </style>
    <a href="https://41dt5g.share-na2.hsforms.com/2K9_0lqxDTzeMPY4ZyJkBLQ" target="_blank" class="form-btn">📝 Open the Access Form</a>
""", unsafe_allow_html=True)

# Once clicked (user returns and confirms)
st.info("✅ Once you've submitted the form, check below to continue:")
form_done = st.checkbox("✅ I have filled and submitted the access form")

if not form_done:
    st.warning("Please confirm the form submission before proceeding.")
    st.stop()
# ============================================================
# ⚡ Flashmind Analysis Engine (runs when admin/unlocked user clicks button)
# ============================================================
topic = st.text_input("📘 Enter Analysis Topic")

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic.")
    else:
        st.info("Processing via Flashmind Engine...")
        prompt = build_locked_prompt(topic)
        # call engine
        result = flashmind_engine(prompt, ENGINE_KEY)

        st.markdown("### 🧠 Flashmind Results")
        st.markdown(f"**Analysis 1:**\n{result['Analysis 1']}")
        st.markdown(f"**Analysis 2:**\n{result['Analysis 2']}")
        st.markdown(f"**Summary:**\n{result['Summary']}")

        st.success("✅ Analysis complete. Demo valid for one use per User ID.")
        # record lock (user_id only)
        register_user_lock(user_id, lock_data)





