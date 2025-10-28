# === ⚡ Flashmind Analyzer (Final: robust timestamp handling) ===
# Author: Arjit | Flashmind Systems © 2025
#
# NOTE: Put these in Streamlit Secrets:
# FLASHMIND_KEY, LOCK_API_KEY, ADMIN_PASSWORD (or ADMIN_PASSWORD_BASE64)

import streamlit as st
import requests
import json
import hashlib
import base64
from datetime import datetime, timedelta, timezone

# ------------------------
# Configuration / Secrets
# ------------------------
ENGINE_KEY = st.secrets.get("FLASHMIND_KEY")
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY")
LOCK_FILE_URL = "https://api.github.com/gists/7cd8a2b265c34b1592e88d1d5b863a8a"
LOCK_DURATION_DAYS = 30

# Admin password: plain or base64 fallback
_ADMIN_PLAIN = st.secrets.get("ADMIN_PASSWORD")
if not _ADMIN_PLAIN and st.secrets.get("ADMIN_PASSWORD_BASE64"):
    try:
        _ADMIN_PLAIN = base64.b64decode(st.secrets["ADMIN_PASSWORD_BASE64"]).decode("utf-8")
    except Exception:
        _ADMIN_PLAIN = None
ADMIN_PASSWORD = _ADMIN_PLAIN

# ------------------------
# Utilities
# ------------------------
def get_user_ip():
    try:
        res = requests.get("https://api.ipify.org?format=json", timeout=5)
        return res.json().get("ip", "unknown")
    except Exception:
        return "unknown"

def mask_ip(ip):
    return hashlib.sha256(ip.encode()).hexdigest()[:10] if ip != "unknown" else "anonymous"

def parse_timestamp(ts_str):
    """
    Try safe parsing of many common timestamp formats.
    Returns a timezone-aware UTC datetime on success, else None.
    """
    if not ts_str or not isinstance(ts_str, str):
        return None
    # Try ISO first (handles 'YYYY-MM-DDTHH:MM:SS[.ffffff]' and with offset)
    try:
        dt = datetime.fromisoformat(ts_str)
        # fromisoformat may return naive or offset-aware; convert to UTC naive for internal consistency
        if dt.tzinfo:
            dt_utc = dt.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            dt_utc = dt
        return dt_utc
    except Exception:
        pass

    # Try common formats
    common_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%d-%m-%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S"
    ]
    for fmt in common_formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt
        except Exception:
            continue
    return None

def normalize_timestamp(ts_input):
    """
    Accepts a stored value (string or dict), returns an ISO-8601 UTC string.
    If parse fails, returns current UTC isoformat (now).
    """
    if isinstance(ts_input, str):
        parsed = parse_timestamp(ts_input)
        if parsed:
            return parsed.replace(tzinfo=None).isoformat()
        else:
            return datetime.utcnow().isoformat()
    elif isinstance(ts_input, dict):
        # If someone stored { "timestamp": "..." } (odd case), handle
        t = ts_input.get("timestamp")
        return normalize_timestamp(t)
    else:
        return datetime.utcnow().isoformat()

# ------------------------
# Gist read/write + migration
# ------------------------
def save_lock_data(data):
    """Save clean user_id -> {timestamp: ISO} structure to Gist."""
    clean = {uid: {"timestamp": v.get("timestamp")} for uid, v in data.items()}
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    payload = {"files": {"lock.json": {"content": json.dumps(clean, indent=4)}}}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception:
        return False

def load_lock_data():
    """
    Load lock data. Migrate legacy formats:
      - legacy dict: "ip": "timestamp"  -> convert ip -> user_id and normalize timestamp
      - legacy dict with nested user_id/ip fields -> normalize
    Overwrites Gist with cleaned user_id-keyed data (privacy-safe).
    """
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"}
        res = requests.get(LOCK_FILE_URL, headers=headers, timeout=10)
        gist = res.json() if res.status_code == 200 else {}
        files = gist.get("files", {})
        content = "{}"
        if "lock.json" in files:
            content = files["lock.json"]["content"]
        elif files:
            content = next(iter(files.values()))["content"]
        raw = json.loads(content)
    except Exception:
        raw = {}

    fixed = {}
    for k, v in raw.items():
        # If v is a simple timestamp string and key is probably IP (legacy)
        if isinstance(v, str):
            uid = mask_ip(k)
            fixed[uid] = {"timestamp": normalize_timestamp(v)}
        elif isinstance(v, dict):
            # If dict contains 'user_id' and 'timestamp'
            if "user_id" in v and "timestamp" in v:
                uid = v.get("user_id") or mask_ip(k)
                fixed[uid] = {"timestamp": normalize_timestamp(v.get("timestamp"))}
            # If dict is simply { "timestamp": "..." } with key being user_id already
            elif "timestamp" in v:
                uid = k
                fixed[uid] = {"timestamp": normalize_timestamp(v.get("timestamp"))}
            else:
                # Unknown dict shape — attempt best-effort: stringify subfields or set now
                uid = k
                fixed[uid] = {"timestamp": datetime.utcnow().isoformat()}
        else:
            # Unknown type, set now
            uid = k
            fixed[uid] = {"timestamp": datetime.utcnow().isoformat()}

    # Overwrite gist with normalized format to avoid repeated errors
    save_lock_data(fixed)
    return fixed

# ------------------------
# Lock checks and registering
# ------------------------
def is_user_locked(user_id, data):
    if user_id not in data:
        return False
    ts_str = data[user_id].get("timestamp")
    parsed = parse_timestamp(ts_str)
    if not parsed:
        # treat invalid as already normalized earlier, but fallback to not locked
        return False
    # Compare in UTC (both naive datetimes representing UTC)
    return datetime.utcnow() - parsed < timedelta(days=LOCK_DURATION_DAYS)

def register_user_lock(user_id, data):
    data[user_id] = {"timestamp": datetime.utcnow().isoformat()}
    save_lock_data(data)

# ------------------------
# Flashmind Core (unchanged except safety)
# ------------------------
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

# ------------------------
# Streamlit UI
# ------------------------
# ------------------------
# Streamlit UI (fixed lock guard)
# ------------------------
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

# ------------------------
# Early exit if locked
# ------------------------
if locked:
    st.error(
        "⚠ You have already used this Flashmind demo in the past **30 days**.\n\n"
        "Please contact admin for enterprise or extended access."
    )
    st.stop()

# ------------------------
# Admin Panel
# ------------------------
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
                    ts_str = val.get("timestamp")
                    parsed = parse_timestamp(ts_str)
                    if parsed:
                        ist = parsed + timedelta(hours=5, minutes=30)
                        days_ago = (datetime.utcnow() - parsed).days
                        st.write(f"- 🧠 `{uid}` | 📅 {ist.strftime('%Y-%m-%d')} | 🕒 {ist.strftime('%H:%M:%S')} | ⏱️ {days_ago} days ago")
                    else:
                        st.write(f"- 🧠 `{uid}` | 🕒 Invalid timestamp (`{ts_str}`)")
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

# ------------------------
# Access Form + Analysis UI
# ------------------------
st.markdown("### 📝 Step 1: Complete Access Form")
st.write("Please fill out the form below before proceeding:")
form_url = "https://41dt5g.share-na2.hsforms.com/2K9_0lqxDTzeMPY4ZyJkBLQ"

col1, col2 = st.columns([2, 1])
with col1:
    st.markdown(f'<a href="{form_url}" target="_blank" class="form-btn">📝 Open the Access Form</a>', unsafe_allow_html=True)
with col2:
    try:
        st.link_button("Click here if form didn’t open", form_url)
    except Exception:
        st.markdown(f'[Click here if form didn\'t open]({form_url})', unsafe_allow_html=True)

form_done = st.checkbox("✅ I have filled and submitted the access form")
if not form_done:
    st.warning("Please confirm after submitting the form.")
    st.stop()

# ------------------------
# Analysis Runner
# ------------------------
topic = st.text_input("📘 Enter Analysis Topic")
if st.button("🚀 Run Flashmind Analysis"):
    # double-check lock before running (in case admin locked mid-session)
    lock_data = load_lock_data()
    if is_user_locked(user_id, lock_data):
        st.error("🚫 You’re locked for 30 days. Please contact admin.")
        st.stop()

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

        # Register lock immediately after success
        register_user_lock(user_id, lock_data)
        st.success("✅ Analysis complete. Demo locked for 30 days.")
        st.rerun()

# Access form (styled link + fallback)
st.markdown("### 📝 Step 1: Complete Access Form")
st.write("Please fill out the form below before proceeding:")
form_url = "https://41dt5g.share-na2.hsforms.com/2K9_0lqxDTzeMPY4ZyJkBLQ"

col1, col2 = st.columns([2,1])
with col1:
    st.markdown(f'<a href="{form_url}" target="_blank" class="form-btn">📝 Open the Access Form</a>', unsafe_allow_html=True)
with col2:
    try:
        st.link_button("Click here if form didn’t open", form_url)
    except Exception:
        st.markdown(f'[Click here if form didn\'t open]({form_url})', unsafe_allow_html=True)

form_done = st.checkbox("✅ I have filled and submitted the access form")
if not form_done:
    st.warning("Please confirm after submitting the form.")
    st.stop()

# Run engine
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


