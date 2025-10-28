# === ⚡ Flashmind Analyzer (Privacy-Safe + Flashmind Engine) ===
# Author: Arjit | Flashmind Systems © 2025
#
# NOTE: Add your secrets in Streamlit "Secrets" (recommended):
#   [secrets]
#   FLASHMIND_KEY = "your_engine_key"
#   LOCK_API_KEY = "your_github_token_with_gist_scope"
#   ADMIN_PASSWORD = "your_admin_password"
#   # or encoded:
#   ADMIN_PASSWORD_BASE64 = "YmFzZTY0X2V4YW1wbGVfcGFzc3dvcmQ="

import streamlit as st
import requests
import json
import hashlib
import base64
from datetime import datetime, timedelta, timezone

# ============================================================
# 🔐 Configuration (Secrets)
# ============================================================
ENGINE_KEY = st.secrets.get("FLASHMIND_KEY")
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY")
LOCK_FILE_URL = "https://api.github.com/gists/7cd8a2b265c34b1592e88d1d5b863a8a"
LOCK_DURATION_DAYS = 30

# Prefer plain password; fallback to base64 decode
_ADMIN_PLAIN = st.secrets.get("ADMIN_PASSWORD")
if not _ADMIN_PLAIN and st.secrets.get("ADMIN_PASSWORD_BASE64"):
    try:
        _ADMIN_PLAIN = base64.b64decode(st.secrets["ADMIN_PASSWORD_BASE64"]).decode("utf-8")
    except Exception:
        _ADMIN_PLAIN = None
ADMIN_PASSWORD = _ADMIN_PLAIN

# ============================================================
# ⚙️ Utilities
# ============================================================
def get_user_ip():
    """Fetch the user's public IP (used only to derive stable ID, not stored)."""
    try:
        res = requests.get("https://api.ipify.org?format=json", timeout=5)
        return res.json().get("ip", "unknown")
    except Exception:
        return "unknown"

def mask_ip(ip):
    """Generate a consistent anonymous ID for each user."""
    return hashlib.sha256(ip.encode()).hexdigest()[:10] if ip != "unknown" else "anonymous"

def save_lock_data(data):
    """Overwrite lock.json in gist with only user_id + timestamp."""
    clean_data = {uid: {"timestamp": v.get("timestamp")} for uid, v in data.items()}
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    payload = {"files": {"lock.json": {"content": json.dumps(clean_data, indent=4)}}}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception:
        return False

def load_lock_data():
    """Read lock data and migrate legacy keys if needed."""
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"}
        gist = requests.get(LOCK_FILE_URL, headers=headers, timeout=10).json()
        content = gist.get("files", {}).get("lock.json", {}).get("content", "{}")
        data = json.loads(content)

        fixed = {}
        for key, val in data.items():
            if isinstance(val, str):
                uid = mask_ip(key)
                fixed[uid] = {"timestamp": val}
            elif isinstance(val, dict):
                uid = val.get("user_id", key)
                ts = val.get("timestamp", datetime.utcnow().isoformat())
                fixed[uid] = {"timestamp": ts}

        save_lock_data(fixed)  # overwrite with cleaned format
        return fixed
    except Exception:
        return {}

def is_user_locked(user_id, data):
    """Check if user is still within lock duration."""
    if user_id not in data:
        return False
    try:
        ts = datetime.fromisoformat(data[user_id]["timestamp"])
        return datetime.utcnow() - ts < timedelta(days=LOCK_DURATION_DAYS)
    except Exception:
        return False

def register_user_lock(user_id, data):
    """Register user lock and update gist."""
    data[user_id] = {"timestamp": datetime.utcnow().isoformat()}
    save_lock_data(data)

# ============================================================
# 🧠 Flashmind Engine Core
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
    """Run through three models and return responses."""
    if not key:
        return {"Analysis 1": "❌ Engine key missing", "Analysis 2": "⚠ None", "Summary": "⚠ None"}

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
# 🖥️ Streamlit UI
# ============================================================
st.set_page_config(page_title="⚡ Flashmind Analyzer", page_icon="⚡")
st.title("⚡ Flashmind Analyzer")

if LOCK_API_KEY:
    st.caption("✅ Connected with Flashmind API")
else:
    st.caption("❌ LOCK_API_KEY missing — add in Streamlit Secrets")

st.caption("One use per user (30-day lock) | © 2025 Flashmind Systems")

ip = get_user_ip()
user_id = mask_ip(ip)
st.write(f"🔒 User ID: `{user_id}`")

lock_data = load_lock_data()
locked = is_user_locked(user_id, lock_data)

# ============================================================
# 🔐 Admin Access (via Secrets)
# ============================================================
with st.sidebar.expander("🔐 Admin Access", expanded=False):
    if not ADMIN_PASSWORD:
        st.warning("Admin access disabled. Add ADMIN_PASSWORD or ADMIN_PASSWORD_BASE64 in secrets.")
    else:
        pwd = st.text_input("Enter Admin Password", type="password")
        if pwd == ADMIN_PASSWORD:
            st.success("✅ Admin Access Granted")

            lock_data = load_lock_data()
            if not lock_data:
                st.info("No locked users yet.")
            else:
                st.markdown("### 📜 Locked Users (IST)")
                for uid, val in lock_data.items():
                    try:
                        ts = datetime.fromisoformat(val["timestamp"]).replace(tzinfo=timezone.utc)
                        local_ts = ts + timedelta(hours=5, minutes=30)
                        days_ago = (datetime.utcnow() - ts).days
                        st.write(
                            f"- 🧠 `{uid}` | 📅 {local_ts.strftime('%Y-%m-%d')} | 🕒 {local_ts.strftime('%H:%M:%S')} | ⏱️ {days_ago} days ago"
                        )
                    except Exception:
                        st.write(f"- 🧠 `{uid}` | 🕒 Invalid timestamp")

            st.markdown("---")
            unlock_id = st.text_input("Enter User ID to Unlock")
            if st.button("🔓 Unlock User"):
                if unlock_id in lock_data:
                    del lock_data[unlock_id]
                    save_lock_data(lock_data)
                    st.success(f"✅ Unlocked `{unlock_id}` successfully.")
                    st.rerun()
                else:
                    st.warning("User ID not found.")

            if st.button("🧹 Clear All Locks"):
                save_lock_data({})
                st.success("✅ All locks cleared.")
                st.rerun()

# ============================================================
# 📝 Access Form (with fallback link)
# ============================================================
st.markdown("### 📝 Step 1: Complete Access Form")
st.write("Please fill out the form below before proceeding:")

form_url = "https://41dt5g.share-na2.hsforms.com/2K9_0lqxDTzeMPY4ZyJkBLQ"

col1, col2 = st.columns([2, 1])
with col1:
    st.markdown(
        f"""<a href="{form_url}" target="_blank" class="form-btn">
        📝 Open the Access Form</a>""",
        unsafe_allow_html=True,
    )
with col2:
    st.link_button("Click here if form didn’t open", form_url)

form_done = st.checkbox("✅ I have filled and submitted the access form")
if not form_done:
    st.warning("Please confirm after submitting the form.")
    st.stop()

# ============================================================
# ⚡ Flashmind Engine Run
# ============================================================
topic = st.text_input("📘 Enter Analysis Topic")

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic first.")
    else:
        st.info("Processing via Flashmind Engine...")
        prompt = build_locked_prompt(topic)
        result = flashmind_engine(prompt, ENGINE_KEY)

        st.subheader("🔍 Analysis 1")
        st.write(result["Analysis 1"])
        st.subheader("🔍 Analysis 2")
        st.write(result["Analysis 2"])
        st.subheader("🧾 Final Summary")
        st.write(result["Summary"])

        register_user_lock(user_id, lock_data)
        st.success("✅ Analysis complete. Demo locked for 30 days.")
