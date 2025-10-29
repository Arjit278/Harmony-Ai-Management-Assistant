# === ⚡ Flashmind Analyzer (Stable Lock + Admin Bypass Edition) ===
# Author: Arjit | Flashmind Systems © 2025

import streamlit as st
import requests, json, hashlib, base64, uuid
from datetime import datetime, timedelta, timezone

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
# 🧩 Utility functions
# ------------------------
def get_user_ip():
    try:
        return requests.get("https://api.ipify.org?format=json", timeout=5).json().get("ip", "unknown")
    except Exception:
        return "unknown"

def mask_ip(ip):
    return hashlib.sha256(ip.encode()).hexdigest()[:10] if ip and ip != "unknown" else "anonymous"

def get_socket_id():
    if "socket_id" not in st.session_state:
        st.session_state["socket_id"] = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:10]
    return st.session_state["socket_id"]

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
# 🗂️ Lock file helpers
# ------------------------
def save_lock_data(data: dict):
    if not LOCK_API_KEY:
        st.error("❌ Missing LOCK_API_KEY in Streamlit secrets.")
        return False
    payload = {"files": {"lock.json": {"content": json.dumps(data, indent=4)}}}
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception as e:
        st.error(f"⚠ Error writing to lock.json: {e}")
        return False

def load_lock_data():
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"}
        res = requests.get(LOCK_FILE_URL, headers=headers, timeout=10)
        content = res.json().get("files", {}).get("lock.json", {}).get("content", "{}")
        data = json.loads(content)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}

    fixed = {}
    for k, v in data.items():
        if isinstance(v, dict):
            uid = v.get("user_id", k)
            sid = v.get("socket_id", "")
            ts = normalize_timestamp(v.get("timestamp"))
        else:
            uid = k
            sid = ""
            ts = normalize_timestamp(v)
        fixed[uid] = {"user_id": uid, "socket_id": sid, "timestamp": ts}
    return fixed

def deduplicate_locks(data):
    seen_uid, seen_sid, clean = set(), set(), {}
    for uid, entry in data.items():
        sid = entry.get("socket_id", "")
        if uid in seen_uid or (sid and sid in seen_sid):
            continue
        clean[uid] = entry
        seen_uid.add(uid)
        if sid:
            seen_sid.add(sid)
    if clean != data:
        save_lock_data(clean)
    return clean

def is_user_locked(user_id, socket_id, data):
    for entry in data.values():
        ts = parse_timestamp(entry.get("timestamp"))
        if not ts:
            continue
        if entry.get("user_id") == user_id or entry.get("socket_id") == socket_id:
            if datetime.utcnow() - ts < timedelta(days=LOCK_DURATION_DAYS):
                return True
    return False

def register_user_lock(user_id, socket_id, data):
    data[user_id] = {
        "user_id": user_id,
        "socket_id": socket_id,
        "timestamp": datetime.utcnow().isoformat(),
    }
    save_lock_data(data)

def unlock_user(target, data):
    found = False
    for uid in list(data.keys()):
        if (
            uid == target
            or mask_ip(target) == uid
            or data[uid].get("socket_id") == target
        ):
            del data[uid]
            found = True
    if found:
        save_lock_data(data)
    return found

def force_unlock_current(user_id, socket_id):
    for key in ["socket_id", "_is_locked", "admin_bypass"]:
        if key in st.session_state:
            del st.session_state[key]
    st.success(f"✅ Force unlocked this session ({user_id} / {socket_id}). Please rerun.")
    st.rerun()

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
        return {"Analysis 1": "❌ Engine key missing", "Analysis 2": "⚠ None", "Summary": "⚠ None"}

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
        except Exception:
            return "⚠ Engine unavailable."

    return {
        "Analysis 1": call("groq/compound-mini"),
        "Analysis 2": call("llama-3.1-8b-instant"),
        "Summary": call("groq/compound"),
    }

# ------------------------
# 🖥️ Streamlit UI
# ------------------------
st.set_page_config(page_title="⚡ Flashmind Analyzer", page_icon="⚡")
st.title("⚡ Flashmind Analyzer")
st.caption("One use per user (30-day lock) | © 2025 Flashmind Systems")

ip = get_user_ip()
user_id = mask_ip(ip)
socket_id = get_socket_id()
st.write(f"🔒 User ID: `{user_id}` | 🔌 Socket ID: `{socket_id}`")

lock_data = deduplicate_locks(load_lock_data())

# ------------------------
# 🔐 Admin Panel
# ------------------------
admin_bypass = False
with st.sidebar.expander("🔐 Admin Access", expanded=True):
    if not ADMIN_PASSWORD:
        st.warning("Admin password missing in secrets.")
    else:
        pwd = st.text_input("Enter Admin Password", type="password")
        if pwd == ADMIN_PASSWORD:
            st.success("✅ Admin Access Granted")
            st.info("🛡️ Admin bypass enabled — no lock restrictions will apply for this session.")
            admin_bypass = True
            st.session_state["admin_bypass"] = True

            lock_data = deduplicate_locks(load_lock_data())

            if not lock_data:
                st.info("No locked users yet.")
            else:
                st.markdown("### 📜 Locked Users (IST)")
                for uid, val in lock_data.items():
                    ts = parse_timestamp(val.get("timestamp"))
                    if ts:
                        ist = ts + timedelta(hours=5, minutes=30)
                        st.write(f"🧠 `{uid}` | 🔌 `{val.get('socket_id','')}` | 📅 {ist:%Y-%m-%d} 🕒 {ist:%H:%M:%S}")
            st.markdown("---")

            target = st.text_input("Enter User ID / IP / Socket ID to Unlock")
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("🔓 Unlock User"):
                    if unlock_user(target.strip(), lock_data):
                        st.success(f"✅ Unlocked `{target}`")
                        st.rerun()
                    else:
                        st.warning("No match found.")
            with col2:
                if st.button("🧹 Clear All Locks"):
                    save_lock_data({})
                    st.success("✅ All locks cleared.")
                    st.rerun()
            with col3:
                if st.button("🚪 Force Unlock (Current User)"):
                    force_unlock_current(user_id, socket_id)
        elif pwd:
            st.error("❌ Incorrect password.")

# ------------------------
# 🧱 Lock Check
# ------------------------
if not admin_bypass and "admin_bypass" not in st.session_state:
    if is_user_locked(user_id, socket_id, lock_data):
        st.error("🚫 You’ve already used Flashmind in the last 30 days. Please contact admin.")
        st.stop()

# ------------------------
# Access Form
# ------------------------
st.markdown("### 📝 Step 1: Complete Access Form")
form_url = "https://41dt5g.share-na2.hsforms.com/2K9_0lqxDTzeMPY4ZyJkBLQ"
st.link_button("📝 Open the Access Form", form_url)
if not st.checkbox("✅ I have filled and submitted the access form"):
    st.warning("Please confirm after submitting the form.")
    st.stop()

# ------------------------
# Topic Input
# ------------------------
st.markdown("""
<style>
.topic-label {
    font-size: 1.7em;
    font-weight: 800;
    color: #0055ff;
    text-align: center;
    margin-top: 25px;
    margin-bottom: 15px;
    text-shadow: 0 0 6px rgba(0, 85, 255, 0.2);
}
.stTextInput > div > div > input {
    font-size: 1.15em !important;
    padding: 0.7em 1em !important;
    border-radius: 10px !important;
    border: 2px solid #0055ff !important;
    box-shadow: 0 0 10px rgba(0, 85, 255, 0.25) !important;
}
</style>
<div class="topic-label">📘 Enter Analysis Topic</div>
""", unsafe_allow_html=True)

topic = st.text_input("", placeholder="Type your analysis topic here...")

# ------------------------
# 🚀 Run Analysis
# ------------------------
if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic.")
        st.stop()

    st.info("☕ Processing via Flashmind Engine...")
    prompt = build_prompt(topic)
    result = flashmind_engine(prompt, ENGINE_KEY)

    st.subheader("🧠 Flashmind Analysis")
    st.write(result["Analysis"])

    # Only register lock if NOT admin
    if not admin_bypass and "admin_bypass" not in st.session_state:
        lock_data = load_lock_data()
        register_user_lock(user_id, socket_id, lock_data)
        st.success("✅ Analysis complete. Demo locked for 30 days.")
        st.rerun()
    else:
        st.success("✅ Admin bypass active — analysis completed without lock.")

