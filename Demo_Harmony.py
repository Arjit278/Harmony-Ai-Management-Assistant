# === ⚡ Flashmind Analyzer (Stable Lock + Admin Bypass Edition) ===
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
# ---------- Begin: Socket-only Locking (no admin logs, mobile locked) ----------
# ------------------------

def detect_mobile():
    """
    Best-effort mobile detection — reads HTTP_USER_AGENT env var if available
    or query param 'ua' via Streamlit experimental_get_query_params.
    Returns True for likely mobile UAs.
    """
    ua = os.environ.get("HTTP_USER_AGENT", "") or os.environ.get("USER_AGENT", "")
    try:
        if not ua:
            params = st.experimental_get_query_params()
            ua = params.get("ua", [""])[0]
    except Exception:
        pass
    ua = (ua or "").lower()
    mobile_indicators = ["mobile", "android", "iphone", "ipad", "ipod", "blackberry", "opera mini"]
    return any(tok in ua for tok in mobile_indicators)

def save_lock_data_socket(data: dict):
    """Save lock.json to the same gist. Data must be dict keyed by socket_id."""
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

def load_lock_data_socket():
    """Load lock.json and return a dict keyed by socket_id.
       Convert legacy formats to socket-keyed entries where possible.
    """
    data = {}
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"} if LOCK_API_KEY else {}
        res = requests.get(LOCK_FILE_URL, headers=headers, timeout=10)
        content = res.json().get("files", {}).get("lock.json", {}).get("content", "{}")
        raw = json.loads(content)
        if isinstance(raw, dict):
            for k, v in raw.items():
                # if entry already keyed by socket_id (10-char hash) use it
                if isinstance(v, dict) and v.get("socket_id"):
                    sid = v["socket_id"]
                    data[sid] = {
                        "socket_id": sid,
                        "timestamp": normalize_timestamp(v.get("timestamp")),
                        **{kk: vv for kk, vv in v.items() if kk not in ("socket_id", "timestamp")}
                    }
                else:
                    # fallback: treat original key as socket_id
                    possible_sid = str(k)
                    # if value is dict and has timestamp or string timestamp, map it
                    ts = None
                    if isinstance(v, dict) and v.get("timestamp"):
                        ts = v.get("timestamp")
                    elif isinstance(v, str):
                        ts = v
                    data[possible_sid] = {
                        "socket_id": possible_sid,
                        "timestamp": normalize_timestamp(ts),
                    }
        else:
            data = {}
    except Exception:
        data = {}

    return data

def deduplicate_locks_socket(data):
    """
    Deduplicate by socket_id only.
    If deduplication changed data, persist it back to gist.
    """
    clean = {}
    changed = False
    for sid, entry in data.items():
        if not sid or not isinstance(sid, str):
            changed = True
            continue
        if sid in clean:
            changed = True
            continue
        clean[sid] = entry
    if changed:
        save_lock_data_socket(clean)
    return clean

def is_socket_locked(socket_id, data):
    """Return True if socket_id present and not expired (LOCK_DURATION_DAYS)."""
    if not socket_id:
        return False
    entry = data.get(socket_id)
    if not entry:
        return False
    ts = parse_timestamp(entry.get("timestamp"))
    if not ts:
        return False
    if datetime.utcnow() - ts < timedelta(days=LOCK_DURATION_DAYS):
        return True
    return False

def register_socket_lock(socket_id, data, meta: dict = None):
    """
    Register socket_id with timestamp.
    meta: optional dict (e.g., device info). If device is mobile, meta will include 'mobile': True.
    Only user actions are recorded here (no admin logs).
    """
    meta = meta or {}
    entry = {
        "socket_id": socket_id,
        "timestamp": datetime.utcnow().isoformat(),
        **meta,
    }
    data[socket_id] = entry
    save_lock_data_socket(data)

def unlock_socket(target_socket_id, data):
    """
    Remove a lock by socket_id. This function does NOT record admin actions anywhere.
    Returns True if removal succeeded.
    """
    found = False
    for sid in list(data.keys()):
        if sid == target_socket_id:
            del data[sid]
            found = True
    if found:
        save_lock_data_socket(data)
    return found

def force_unlock_current_socket(socket_id):
    """
    Force-clears session-level lock state for the current session only.
    This is a local session reset and does NOT write admin logs.
    """
    for key in ["socket_id", "_is_locked", "admin_bypass"]:
        if key in st.session_state:
            del st.session_state[key]
    st.success(f"✅ Force unlocked this session ({socket_id}). Please rerun.")
    st.rerun()

# ------------------------
# ---------- End: Socket-only Locking (no admin logs, mobile locked) ----------
# ------------------------

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
    Analyze topic **{topic}** (2025 Edition) using Flashmind Intel-Strategic.

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

# ✅ FIXED: Added build_prompt wrapper
def build_prompt(topic: str):
    base = build_locked_prompt(topic)
    return base + """
    Provide a **detailed strategic report** including:
    - Analysis from economic, policy, and technological perspectives
    - 2025 global and Indian context where relevant
    - Actionable short-term (0–6 months) and long-term (1–3 years) recommendations
    - Use Markdown formatting with bullet points and subheadings
    - Conclude with top 3 key insights for decision-makers
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
st.set_page_config(page_title="⚡ Harmony Business Intel & strategist Research & Analysis module", page_icon="⚡")
st.title("⚡ Harmony BIA - Flashmind analyzer")
st.caption("Sip your coffee & let us work (Demo, One use per user), it's just a preview of our analytics software (Would like to assist you more, kindly contact harmony team with our website or call on shared numbers for detailed version of demo or to purchase) | © 2025 Harmony-Flashmind Systems")

# get socket id and detect mobile for this session
socket_id = get_socket_id()
is_mobile_session = detect_mobile()
st.write(f"🔌 Socket ID: `{socket_id}` | 📱 Mobile: `{is_mobile_session}`")

# load & dedupe lock data (socket-keyed)
lock_data = load_lock_data_socket()
lock_data = deduplicate_locks_socket(lock_data)

# ------------------------
# 🔐 Admin Panel (shows only socket and mobile ID)
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

            lock_data = load_lock_data_socket()
            lock_data = deduplicate_locks_socket(lock_data)

            if not lock_data:
                st.info("No locked sockets yet.")
            else:
                st.markdown("### 📜 Locked Sockets (IST)")
                # Show only socket ids and mobile flag
                for sid, val in lock_data.items():
                    # skip any unexpected non-socket keys
                    if not isinstance(sid, str) or sid == "":
                        continue
                    # parse timestamp to IST
                    ts = parse_timestamp(val.get("timestamp"))
                    mobile_flag = bool(val.get("mobile", False))
                    if ts:
                        ist = ts + timedelta(hours=5, minutes=30)
                        st.write(f"🔌 `{sid}` | 📱 `{mobile_flag}` | 📅 {ist:%Y-%m-%d} 🕒 {ist:%H:%M:%S}")
                    else:
                        st.write(f"🔌 `{sid}` | 📱 `{mobile_flag}` | 📅 `unknown`")
            st.markdown("---")

            target = st.text_input("Enter Socket ID to Unlock")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔓 Unlock Socket"):
                    if unlock_socket(target.strip(), lock_data):
                        st.success(f"✅ Unlocked `{target}`")
                        st.rerun()
                    else:
                        st.warning("No match found.")
            with col2:
                if st.button("🧹 Clear All Locks"):
                    save_lock_data_socket({})
                    st.success("✅ All locks cleared.")
                    st.rerun()
        elif pwd:
            st.error("❌ Incorrect password.")

# ------------------------
# 🧱 Lock Check (socket-only)
# ------------------------
if not st.session_state.get("admin_bypass", False):
    if is_socket_locked(socket_id, lock_data):
        st.error("🚫 You’ve already used Flashmind in the last few days. Would like to assist you more, kindly contact our team through our website contact us. Thank you once again for chosing us, have a great day!")
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
    prompt = build_prompt(topic)  # ✅ fixed reference
    result = flashmind_engine(prompt, ENGINE_KEY)

    st.subheader("🧠 Flashmind Strategic Analysis")
    st.markdown("### 🔹 Analysis 1")
    st.write(result.get("Analysis 1", "⚠ No response."))
    st.markdown("### 🔹 Analysis 2")
    st.write(result.get("Analysis 2", "⚠ No response."))
    st.markdown("### 🧭 Summary & Recommendations")
    st.write(result.get("Summary", "⚠ No summary available."))

    # Register lock for non-admin: use socket-only and record mobile flag if detected
    if not st.session_state.get("admin_bypass", False):
        lock_data = load_lock_data_socket()
        lock_data = deduplicate_locks_socket(lock_data)
        meta = {}
        if is_mobile_session:
            meta["mobile"] = True
        register_socket_lock(socket_id, lock_data, meta=meta)
        st.success("✅ Analysis complete. Locked for 30 days.")
        time.sleep(1)
        st.rerun()
    else:
        st.success("✅ Admin bypass active — analysis completed without lock.")

