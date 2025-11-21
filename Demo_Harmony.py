# === ⚡ Flashmind Analyzer (Stable Lock + Admin Bypass + Persistent System ID Edition) ===
# Author: Arjit | Flashmind Systems © 2025

import streamlit as st
import requests, json, hashlib, base64, uuid
from datetime import datetime, timedelta, timezone
import os
import time

# ------------------------
# 🔐 Configuration
# ------------------------
ENGINE_KEY = st.secrets.get("FLASHMIND_KEY")
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY")
LOCK_FILE_URL = "https://api.github.com/gists/7cd8a2b265c34b1592e88d1d5b863a8a"
LOCK_DURATION_DAYS = 30

# Admin password (plain or base64)
_ADMIN_PLAIN = st.secrets.get("ADMIN_PASSWORD")
if not _ADMIN_PLAIN and st.secrets.get("ADMIN_PASSWORD_BASE64"):
    try:
        _ADMIN_PLAIN = base64.b64decode(st.secrets["ADMIN_PASSWORD_BASE64"]).decode("utf-8")
    except Exception:
        _ADMIN_PLAIN = None
ADMIN_PASSWORD = _ADMIN_PLAIN

# ------------------------
# 🧩 Browser-persistent system ID (Option D)
# ------------------------

def get_system_id():
    """
    Retrieves a persistent system ID stored in browser localStorage.
    Uses a Streamlit-JS bridge to fetch or create it.
    """
    system_id = st.session_state.get("system_id")

    if system_id:
        return system_id

    js_code = """
    <script>
    let sys = localStorage.getItem("flashmind_system_id");
    if (!sys) {
        sys = self.crypto.randomUUID();
        localStorage.setItem("flashmind_system_id", sys);
    }
    const streamlitMsg = {"system_id": sys};
    window.parent.postMessage(streamlitMsg, "*");
    </script>
    """

    st.components.v1.html(js_code, height=0)

    # Wait for the JS callback
    if "system_id" not in st.session_state:
        st.session_state["system_id"] = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:12]

    return st.session_state["system_id"]

# JS → Python message receiver
def handle_js_message():
    msg = st.experimental_get_query_params()
    if "system_id" in msg:
        st.session_state["system_id"] = msg["system_id"][0]

handle_js_message()

# ------------------------
# Utility functions
# ------------------------

def parse_timestamp(ts_str):
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt if not dt.tzinfo else dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return None

def normalize_timestamp(ts):
    if isinstance(ts, str):
        dt = parse_timestamp(ts)
        return dt.isoformat() if dt else datetime.utcnow().isoformat()
    return datetime.utcnow().isoformat()

# ------------------------
# ---------- Persistent System-ID Locking ----------
# ------------------------

def save_lock_data(data: dict):
    if not LOCK_API_KEY:
        st.error("❌ Missing LOCK_API_KEY.")
        return False
    payload = {"files": {"lock.json": {"content": json.dumps(data, indent=4)}}}
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception as e:
        st.error(f"⚠ Error writing lock.json: {e}")
        return False

def load_lock_data():
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"} if LOCK_API_KEY else {}
        res = requests.get(LOCK_FILE_URL, headers=headers, timeout=10)
        content = res.json().get("files", {}).get("lock.json", {}).get("content", "{}")
        return json.loads(content)
    except Exception:
        return {}

def is_locked(system_id, data):
    entry = data.get(system_id)
    if not entry:
        return False
    ts = parse_timestamp(entry.get("timestamp"))
    if not ts:
        return False
    return datetime.utcnow() - ts < timedelta(days=LOCK_DURATION_DAYS)

def register_lock(system_id, data):
    data[system_id] = {
        "system_id": system_id,
        "timestamp": datetime.utcnow().isoformat(),
    }
    save_lock_data(data)

def unlock(system_id, data):
    if system_id in data:
        del data[system_id]
        save_lock_data(data)
        return True
    return False

# ------------------------
# ⚡ Flashmind Engine
# ------------------------

def get_references(query):
    return [
        f"https://www.brookings.edu/research/{query.replace(' ', '-')}-2025",
        f"https://www.weforum.org/agenda/{query.replace(' ', '-')}-trends",
        f"https://www.mckinsey.com/{query.replace(' ', '-')}-insights-2025",
        f"https://www.hbs.edu/faculty/Pages/item.aspx?topic={query.replace(' ', '-')}",
        f"https://www.pwc.com/gx/en/issues/{query.replace(' ', '-')}-future-outlook.html",
        f"https://www2.deloitte.com/global/en/pages/strategy-operations/articles/{query.replace(' ', '-')}-report.html",
        f"https://www.imf.org/en/Publications/search?when=After&series=Research&title={query.replace(' ', '+')}",
    ]

def build_locked_prompt(topic: str):
    refs_md = "\n".join([f"- {r}" for r in get_references(topic)])
    return f"""
    Analyze topic **{topic}** using Flashmind Intel-Strategic.

    1. Identify Root Causes (100% total)
    2. Recommend actionable strategies

    | Root Cause | % | Solution |
    |------------|---|----------|
    | Cause 1 | 25 | Solution |
    | Cause 2 | 35 | Solution |
    | Cause 3 | 40 | Solution |

    {refs_md}
    """

def build_prompt(topic: str):
    base = build_locked_prompt(topic)
    return base + """
    Provide a detailed 2025 report with:
    - Economic, policy, tech perspectives
    - India + global view
    - Actions (0–6 months) + (1–3 years)
    - Markdown formatting
    """

def flashmind_engine(prompt, key):
    if not key:
        return {"Analysis 1": "❌ Engine key missing",
                "Analysis 2": "⚠ None",
                "Summary": "⚠ None"}

    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    def call(model):
        try:
            res = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json={"model": model, "messages": [{"role": "user", "content": prompt}]},
                timeout=60,
            )
            return res.json()["choices"][0]["message"]["content"].strip()
        except:
            return "⚠ Engine unavailable."

    return {
        "Analysis 1": call("groq/compound-mini"),
        "Analysis 2": call("llama-3.1-8b-instant"),
        "Summary": call("groq/compound"),
    }

# ------------------------
# 🖥️ Streamlit UI
# ------------------------

st.set_page_config(page_title="⚡ Harmony Business Intel Analysis", page_icon="⚡")
st.title("⚡ Harmony BIA - Flashmind Analyzer")

system_id = get_system_id()
st.write(f"🆔 Persistent System ID: `{system_id}`")

lock_data = load_lock_data()

# ------------------------
# Admin Panel
# ------------------------

admin_bypass = False
with st.sidebar.expander("🔐 Admin Access", expanded=True):
    pwd = st.text_input("Enter Admin Password", type="password")
    if pwd == ADMIN_PASSWORD:
        st.success("Admin Access Granted")
        admin_bypass = True
        st.session_state["admin_bypass"] = True

        st.subheader("📜 Locked IDs")
        for sid, v in lock_data.items():
            ts = parse_timestamp(v.get("timestamp"))
            if ts:
                ist = ts + timedelta(hours=5, minutes=30)
                st.write(f"🆔 `{sid}` | {ist:%Y-%m-%d %H:%M:%S}")
            else:
                st.write(f"🆔 `{sid}`")

        target = st.text_input("System ID to Unlock")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔓 Unlock"):
                if unlock(target.strip(), lock_data):
                    st.success("Unlocked")
                    st.rerun()
        with col2:
            if st.button("🧹 Clear All Locks"):
                save_lock_data({})
                st.success("All Cleared")
                st.rerun()

# ------------------------
# Lock Check
# ------------------------

if not st.session_state.get("admin_bypass", False):
    if is_locked(system_id, lock_data):
        st.error("🚫 You have already used your trial. Please contact Harmony Team.")
        st.stop()

# ------------------------
# Access Form
# ------------------------

st.markdown("### 📝 Step 1: Complete Access Form")
form_url = "https://41dt5g.share-na2.hsforms.com/2K9_0lqxDTzeMPY4ZyJkBLQ"
st.link_button("📝 Open the Access Form", form_url)
if not st.checkbox("I have submitted the form"):
    st.stop()

# ------------------------
# Topic Input
# ------------------------

topic = st.text_input("Enter Analysis Topic")

# ------------------------
# Run Analysis
# ------------------------

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic.")
        st.stop()

    st.info("☕ Processing...")
    prompt = build_prompt(topic)
    result = flashmind_engine(prompt, ENGINE_KEY)

    st.subheader("🔹 Analysis 1")
    st.write(result["Analysis 1"])
    st.subheader("🔹 Analysis 2")
    st.write(result["Analysis 2"])
    st.subheader("🔹 Summary")
    st.write(result["Summary"])

    if not st.session_state.get("admin_bypass", False):
        lock_data = load_lock_data()
        register_lock(system_id, lock_data)
        st.success("✅ Analysis complete — now locked for 30 days.")
        time.sleep(1)
        st.rerun()
    else:
        st.success("Admin mode — no lock applied.")
