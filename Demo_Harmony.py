# === ⚡ Flashmind Analyzer (IP/User-Locked Edition) ===
# Author: Arjit | Flashmind Systems © 2025
# One-use-per-IP, have a great day !!!

import streamlit as st
import requests
import json
import hashlib
from datetime import datetime, timedelta

# ============================================================
# 🔒 Backend Keys
# ============================================================
ENGINE_KEY = st.secrets.get("FLASHMIND_KEY", None)
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY", None)  # GitHub token with gist permission
LOCK_FILE_URL = "https://api.github.com/gists/7cd8a2b265c34b1592e88d1d5b863a8a"
LOCK_DURATION_DAYS = 30
ADMIN_PASSWORD = "Harmony_Chand@9028"

# ============================================================
# === Utilities
# ============================================================
def get_user_ip():
    """Fetch client IP via external API."""
    try:
        res = requests.get("https://api.ipify.org?format=json", timeout=5)
        return res.json().get("ip", "unknown")
    except Exception:
        return "unknown"

def mask_ip(ip):
    """Return hashed User ID instead of raw IP."""
    if ip == "unknown":
        return "anonymous-user"
    return hashlib.sha256(ip.encode()).hexdigest()[:10]

def load_lock_data():
    """Load existing lock data from GitHub Gist."""
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"}
        gist = requests.get(LOCK_FILE_URL, headers=headers, timeout=10).json()
        files = gist.get("files", {})
        if "lock.json" in files:
            content = files["lock.json"].get("content", "{}")
        else:
            content = next(iter(files.values())).get("content", "{}")
        return json.loads(content)
    except Exception:
        return {}

def save_lock_data(lock_data):
    """Save updated lock data to GitHub Gist (lock.json)."""
    headers = {
        "Authorization": f"token {LOCK_API_KEY}",
        "Accept": "application/vnd.github+json"
    }
    payload = {"files": {"lock.json": {"content": json.dumps(lock_data, indent=4)}}}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception:
        return False

def is_user_locked(ip, lock_data):
    """Check if user is within 30-day lock window."""
    if ip not in lock_data:
        return False
    try:
        last_ts = datetime.fromisoformat(lock_data[ip])
        return datetime.now() - last_ts < timedelta(days=LOCK_DURATION_DAYS)
    except Exception:
        return False

def register_user_lock(ip, lock_data):
    """Register user IP with current timestamp."""
    lock_data[ip] = str(datetime.utcnow())
    save_lock_data(lock_data)

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
# === Streamlit UI
# ============================================================
st.set_page_config(page_title="⚡ Flashmind Analyzer", page_icon="⚡")
st.title("⚡ Flashmind Analyzer")

# === Connection Check (Silent Display)
if LOCK_API_KEY:
    st.caption("✅ Connected with Flashmind API")
else:
    st.caption("❌ Not connected with Flashmind API")

st.caption("Enjoy your trial — harmonize your efforts with our Business/Industrial Intelligence and Analytics. (One-use-per-user basic version) | © 2025 Flashmind Systems")

ip = get_user_ip()
user_id = mask_ip(ip)
st.write(f"🔒 User ID: `{user_id}`")

lock_data = load_lock_data()
locked = is_user_locked(ip, lock_data)

# ============================================================
# === Admin Access (Hidden Panel)
# ============================================================
with st.sidebar.expander("🔐 Admin Access"):
    admin_password = st.text_input("Enter Admin Password", type="password")
    if admin_password == ADMIN_PASSWORD:
        st.success("✅ Admin Access Granted")

        # View all locked users
        st.subheader("📜 Current Locked Users")
        if not lock_data:
            st.info("No users currently locked.")
        else:
            st.json(lock_data)

        # Unlock specific user
        unlock_ip = st.text_input("Enter IP to Unlock")
        if st.button("🔓 Unlock User"):
            if unlock_ip in lock_data:
                del lock_data[unlock_ip]
                save_lock_data(lock_data)
                st.success(f"User `{unlock_ip}` unlocked successfully.")
            else:
                st.warning("IP not found in lock data.")

        # Clear all locks
        if st.button("🧹 Clear All Locks"):
            save_lock_data({})
            st.success("All locks cleared successfully!")

        # Test connection manually
        if st.button("🔧 Test Gist Connection"):
            try:
                headers = {"Authorization": f"token {LOCK_API_KEY}"}
                res = requests.get(LOCK_FILE_URL, headers=headers, timeout=10)
                if res.status_code == 200:
                    st.success("✅ Connected to GitHub Gist successfully!")
                else:
                    st.error(f"❌ Connection failed (HTTP {res.status_code})")
            except Exception as e:
                st.error(f"⚠ Connection error: {e}")

# ============================================================
# === User Lock Check
# ============================================================
if locked:
    st.error("⚠ You have already used this demo in the past 30 days.\n\nPlease contact admin for enterprise access.")
    st.stop()

# ============================================================
# === Mandatory Pre-Access Form
# ============================================================
st.markdown("### 📝 Step 1: Complete Access Form")
st.markdown("""
Before using Flashmind Analyzer, please complete the short access form below.  
👉 [Open the Access Form](https://41dt5g.share-na2.hsforms.com/2K9_0lqxDTzeMPY4ZyJkBLQ)

Once you’ve submitted it, check the box below to continue.
""")

form_filled = st.checkbox("✅ I have filled and submitted the access form")

if not form_filled:
    st.warning("Please complete the form and check the box to continue.")
    st.stop()

# ============================================================
# === Flashmind Analysis Section
# ============================================================
topic = st.text_input("📄 Enter Analysis Topic")

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic.")
    else:
        st.info("Processing via Flashmind Engine...")
        prompt = build_locked_prompt(topic)
        result = flashmind_engine(prompt, ENGINE_KEY)

        st.subheader("🔍 Analysis 1")
        st.write(result["Analysis 1"])

        st.subheader("🔍 Analysis 2")
        st.write(result["Analysis 2"])

        st.subheader("🧾 Final Strategic Summary")
        st.write(result["Summary"])

        st.success("✅ Complete. Demo valid for one use per user. For detailed access and analytics, kindly contact Admin.")
        register_user_lock(ip, lock_data)
