# === ⚡ Flashmind Analyzer (Final: socket_id + robust timestamp handling) ===
# Author: Arjit | Flashmind Systems © 2025
#
# NOTE: Put these in Streamlit Secrets:
# FLASHMIND_KEY, LOCK_API_KEY, ADMIN_PASSWORD (or ADMIN_PASSWORD_BASE64)

import streamlit as st
import requests, json, hashlib, base64, uuid
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
    """Deterministic masked ID derived from IP (10 hex chars)."""
    return hashlib.sha256(ip.encode()).hexdigest()[:10] if ip != "unknown" else "anonymous"

def get_socket_id():
    """Persistent per-browser-session socket/session id (stored in session_state)."""
    if "socket_id" not in st.session_state:
        st.session_state["socket_id"] = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:10]
    return st.session_state["socket_id"]

def parse_timestamp(ts_str):
    """Try safe parsing of many timestamp formats; return naive UTC datetime or None."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    try:
        dt = datetime.fromisoformat(ts_str)
        # convert offset-aware to naive UTC, or leave naive as-is (assume UTC)
        if dt.tzinfo:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        pass
    formats = [
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%m-%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except Exception:
            continue
    return None

def normalize_timestamp(ts_input):
    """Return an ISO-8601 UTC string for storage, robust to input shapes."""
    if isinstance(ts_input, str):
        parsed = parse_timestamp(ts_input)
        return parsed.replace(tzinfo=None).isoformat() if parsed else datetime.utcnow().isoformat()
    elif isinstance(ts_input, dict):
        return normalize_timestamp(ts_input.get("timestamp"))
    else:
        return datetime.utcnow().isoformat()

# ------------------------
# Gist read/write (store user_id, socket_id, timestamp)
# ------------------------
def save_lock_data(data):
    """
    Save structure:
    { "<user_id>": { "user_id": "<user_id>", "socket_id": "<socket_id>", "timestamp": "<ISO>" }, ... }
    """
    clean = {}
    for uid, v in data.items():
        clean[uid] = {
            "user_id": v.get("user_id", uid),
            "socket_id": v.get("socket_id", ""),
            "timestamp": v.get("timestamp")
        }
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    payload = {"files": {"lock.json": {"content": json.dumps(clean, indent=4)}}}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception:
        return False

def load_lock_data():
    """
    Load lock data and normalize entries. Supports legacy formats:
    - { "1.2.3.4": "timestamp" }  -> will be converted to masked user_id
    - { "user_id": { "timestamp": "..." } }
    - { "user_id": { "user_id": "...", "socket_id": "...", "timestamp": "..." } }
    Existing 10-char hashed IDs are preserved as-is.
    """
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"}
        res = requests.get(LOCK_FILE_URL, headers=headers, timeout=10)
        gist = res.json() if res.status_code == 200 else {}
        files = gist.get("files", {})
        content = files.get("lock.json", {}).get("content", "{}")
        raw = json.loads(content)
    except Exception:
        raw = {}

    fixed = {}
    for k, v in raw.items():
        # Case: legacy simple string (timestamp) keyed by IP or hashed id
        if isinstance(v, str):
            # if key already looks like 10-hex hash, keep as uid; else mask
            if len(k) == 10 and all(c in "0123456789abcdef" for c in k.lower()):
                uid = k
            else:
                uid = mask_ip(k)
            fixed[uid] = {
                "user_id": uid,
                "socket_id": "",
                "timestamp": normalize_timestamp(v)
            }

        # Case: object/dict - possibly contains user_id/socket_id/timestamp
        elif isinstance(v, dict):
            # take explicit fields if present
            stored_uid = v.get("user_id", k)
            stored_sid = v.get("socket_id", "") or ""
            ts = v.get("timestamp", datetime.utcnow().isoformat())

            # preserve hashed uid if it already is one, otherwise mask
            if isinstance(stored_uid, str) and len(stored_uid) == 10 and all(c in "0123456789abcdef" for c in stored_uid.lower()):
                uid = stored_uid
            else:
                uid = mask_ip(stored_uid)

            fixed[uid] = {
                "user_id": uid,
                "socket_id": stored_sid,
                "timestamp": normalize_timestamp(ts)
            }

        else:
            # Unexpected structure — create fallback entry keyed by masked(k)
            uid = mask_ip(str(k))
            fixed[uid] = {
                "user_id": uid,
                "socket_id": "",
                "timestamp": datetime.utcnow().isoformat()
            }

    # Persist normalized cleaned data (overwrites legacy keys)
    save_lock_data(fixed)
    return fixed

# ------------------------
# Lock logic (check and register)
# ------------------------
def is_user_locked(user_id, socket_id, data):
    """Return True if either user_id or socket_id is present within lock window."""
    for entry in data.values():
        if entry.get("user_id") == user_id or (socket_id and entry.get("socket_id") == socket_id):
            ts = parse_timestamp(entry.get("timestamp"))
            if ts and (datetime.utcnow() - ts < timedelta(days=LOCK_DURATION_DAYS)):
                return True
    return False

def register_user_lock(user_id, socket_id, data):
    """Register a lock entry keyed by user_id and containing socket_id."""
    data[user_id] = {
        "user_id": user_id,
        "socket_id": socket_id,
        "timestamp": datetime.utcnow().isoformat()
    }
    save_lock_data(data)

# ------------------------
# Flashmind Core (prompt builder + engine)
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
            return res.json()["choices"][0]["message"]["content"].strip()
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
st.set_page_config(page_title="⚡ Flashmind Analyzer", page_icon="⚡")
st.title("⚡ Flashmind Analyzer")
st.caption("One use per user (30-day lock) | © 2025 Flashmind Systems")

if LOCK_API_KEY:
    st.caption("✅ Connected with Flashmind API")
else:
    st.caption("❌ LOCK_API_KEY missing — add it in Streamlit Secrets")

# identify user (no raw IP stored)
ip = get_user_ip()
user_id = mask_ip(ip)
socket_id = get_socket_id()
st.write(f"🔒 User ID: `{user_id}` | 🔌 Socket ID: `{socket_id}`")

# load lock file
lock_data = load_lock_data()

# ------------------------
# 🔐 Admin Access (visible by default)
# ------------------------
with st.sidebar.expander("🔐 Admin Access", expanded=True):
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
                        st.write(
                            f"- 🧠 `{uid}` | 📅 {ist.strftime('%Y-%m-%d')} | 🕒 {ist.strftime('%H:%M:%S')} | ⏱️ {days_ago} days ago"
                        )
                    else:
                        st.write(f"- 🧠 `{uid}` | 🕒 Invalid timestamp (`{ts_str}`)")

            st.markdown("---")
            unlock_input = st.text_input("Enter User ID / IP / Socket ID to Unlock")

            if st.button("🔓 Unlock User"):
                if not unlock_input.strip():
                    st.warning("Please enter a valid User ID, IP, or Socket ID.")
                else:
                    # Match either masked, IP, or socket ID
                    found_key = None
                    for uid in lock_data.keys():
                        if uid == unlock_input.strip() or uid == mask_ip(unlock_input.strip()):
                            found_key = uid
                            break
                    if found_key:
                        del lock_data[found_key]
                        save_lock_data(lock_data)
                        st.success(f"✅ Unlocked `{unlock_input.strip()}` successfully.")
                        st.rerun()
                    else:
                        st.warning("User ID / IP / Socket ID not found in lock file.")

            if st.button("🧹 Clear All Locks"):
                save_lock_data({})
                st.success("✅ All locks cleared.")
                st.rerun()
        elif pwd:
            st.error("❌ Incorrect password.")


# ------------------------
# Lock check (stop if locked)
# ------------------------
if is_user_locked(user_id, socket_id, lock_data):
    st.error("⚠ You have already used this Flashmind demo in the past 30 days.")
    st.stop()

# ------------------------
# Access form (styled link) + fallback
# ------------------------
st.markdown("### 📝 Step 1: Complete Access Form")
form_url = "https://41dt5g.share-na2.hsforms.com/2K9_0lqxDTzeMPY4ZyJkBLQ"

st.markdown(
    f"""
    <style>
    .form-btn {{
        background:#4CAF50;color:white;border:none;
        padding:0.6em 1.2em;border-radius:8px;
        text-decoration:none;font-weight:500;
    }}
    .form-btn:hover{{background:#45a049;}}
    </style>
    <a href="{form_url}" target="_blank" class="form-btn">📝 Open the Access Form</a>
    """,
    unsafe_allow_html=True
)

# fallback link_button (may not exist on older Streamlit versions)
try:
    st.link_button("Click here if form didn’t open", form_url)
except Exception:
    st.markdown(f'[Click here if form didn\'t open]({form_url})', unsafe_allow_html=True)

if not st.checkbox("✅ I have filled and submitted the access form"):
    st.warning("Please confirm after submitting the form.")
    st.stop()

# ------------------------
# Analysis Runner
# ------------------------
topic = st.text_input("📘 Enter Analysis Topic")
if st.button("🚀 Run Flashmind Analysis"):
    # re-load and double-check lock in case admin changed mid-session
    lock_data = load_lock_data()
    if is_user_locked(user_id, socket_id, lock_data):
        st.error("🚫 You’re locked for 30 days. Please contact admin.")
        st.stop()

    if not topic.strip():
        st.warning("Please enter a topic.")
    else:
        st.info("Sip your coffee... Processing via Flashmind Engine.")
        prompt = build_locked_prompt(topic)
        result = flashmind_engine(prompt, ENGINE_KEY)

        st.subheader("🔍 Analysis 1")
        st.write(result["Analysis 1"])
        st.subheader("🔍 Analysis 2")
        st.write(result["Analysis 2"])
        st.subheader("🧾 Final Strategic Summary")
        st.write(result["Summary"])

        # register lock
        register_user_lock(user_id, socket_id, lock_data)
        st.success("✅ Analysis complete. Demo locked for 30 days.")
        st.rerun()
