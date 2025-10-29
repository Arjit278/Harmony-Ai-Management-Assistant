# === ⚡ Flashmind Analyzer (Final Stable + Persistent Unlock Edition) ===
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
    Force-overwrite the lock.json file on the Gist.
    Includes validation and success/failure indication in Streamlit.
    """
    clean = {
        uid: {
            "user_id": v.get("user_id", uid),
            "socket_id": v.get("socket_id", ""),
            "timestamp": v.get("timestamp", datetime.utcnow().isoformat()),
        }
        for uid, v in data.items()
    }

    headers = {
        "Authorization": f"token {LOCK_API_KEY}",
        "Accept": "application/vnd.github+json",
    }

    payload = {
        "files": {
            "lock.json": {
                "content": json.dumps(clean, indent=4, ensure_ascii=False)
            }
        }
    }

    try:
        # Force overwrite (PATCH is allowed, but we’ll confirm success)
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=15)
        if res.status_code == 200:
            st.toast("✅ Lock data updated successfully.", icon="🔓")
            return True
        else:
            st.error(f"❌ Failed to update lock data: {res.status_code}")
            st.code(res.text)
            return False
    except Exception as e:
        st.error(f"⚠ Error saving lock data: {e}")
        return False

def load_lock_data():
    """Load + normalize + clean lock data from gist."""
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
        if isinstance(v, str):
            if len(k) == 10 and all(c in "0123456789abcdef" for c in k.lower()):
                uid = k
            else:
                uid = mask_ip(k)
            fixed[uid] = {"user_id": uid, "socket_id": "", "timestamp": normalize_timestamp(v)}
        elif isinstance(v, dict):
            stored_uid = v.get("user_id", k)
            stored_sid = v.get("socket_id", "") or ""
            ts = v.get("timestamp", datetime.utcnow().isoformat())
            if isinstance(stored_uid, str) and len(stored_uid) == 10 and all(c in "0123456789abcdef" for c in stored_uid.lower()):
                uid = stored_uid
            else:
                uid = mask_ip(stored_uid)
            fixed[uid] = {"user_id": uid, "socket_id": stored_sid, "timestamp": normalize_timestamp(ts)}
        else:
            uid = mask_ip(str(k))
            fixed[uid] = {"user_id": uid, "socket_id": "", "timestamp": datetime.utcnow().isoformat()}

    save_lock_data(fixed)
    return fixed

# ------------------------
# Lock helpers
# ------------------------
def deduplicate_locks(data):
    """Remove duplicate entries with same socket_id or user_id."""
    seen_uids, seen_sids, cleaned = {}, {}, {}
    for uid, v in data.items():
        sid = v.get("socket_id", "")
        if uid in seen_uids or (sid and sid in seen_sids):
            continue
        cleaned[uid] = v
        seen_uids[uid] = True
        if sid:
            seen_sids[sid] = True
    if cleaned != data:
        save_lock_data(cleaned)
    return cleaned

def unlock_user(target, data):
    """Unlock any user by user_id, socket_id, or IP (masked)."""
    to_remove = []
    for uid, entry in data.items():
        if uid == target or entry.get("socket_id") == target or uid == mask_ip(target):
            to_remove.append(uid)
    for uid in to_remove:
        del data[uid]
    if to_remove:
        save_lock_data(data)
        return True
    return False

def is_user_locked(user_id, socket_id, data):
    """Return True if either user_id or socket_id is present within lock window."""
    for entry in data.values():
        if entry.get("user_id") == user_id or (socket_id and entry.get("socket_id") == socket_id):
            ts = parse_timestamp(entry.get("timestamp"))
            if ts and (datetime.utcnow() - ts < timedelta(days=LOCK_DURATION_DAYS)):
                return True
    return False

def register_user_lock(user_id, socket_id, data):
    """Register a lock entry only if not already locked."""
    if not is_user_locked(user_id, socket_id, data):
        data[user_id] = {
            "user_id": user_id,
            "socket_id": socket_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        save_lock_data(data)

# ------------------------
# Flashmind Core (unchanged)
# ------------------------
def get_references(query):
    return [
        f"https://www.brookings.edu/research/{query.replace(' ', '-')}-2025",
        f"https://www.weforum.org/agenda/{query.replace(' ', '-')}-trends",
        f"https://www.mckinsey.com/{query.replace(' ', '-')}-insights-2025",
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
# Streamlit UI
# ------------------------
st.set_page_config(page_title="⚡ Flashmind Analyzer", page_icon="⚡")
st.title("⚡ Flashmind Analyzer")
st.caption("One use per user (30-day lock) | © 2025 Flashmind Systems")

if LOCK_API_KEY:
    st.caption("✅ Connected with Flashmind API")
else:
    st.caption("❌ LOCK_API_KEY missing — add it in Streamlit Secrets")

ip = get_user_ip()
user_id = mask_ip(ip)
socket_id = get_socket_id()
st.write(f"🔒 User ID: `{user_id}` | 🔌 Socket ID: `{socket_id}`")

lock_data = deduplicate_locks(load_lock_data())

# ------------------------
# 🔐 Admin Access
# ------------------------
with st.sidebar.expander("🔐 Admin Access", expanded=True):
    if not ADMIN_PASSWORD:
        st.warning("Admin access disabled. Add ADMIN_PASSWORD or ADMIN_PASSWORD_BASE64 in secrets.")
    else:
        pwd = st.text_input("Enter Admin Password", type="password")
        if pwd == ADMIN_PASSWORD:
            st.success("✅ Admin Access Granted")
            lock_data = deduplicate_locks(load_lock_data())

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
                if unlock_input.strip():
                    if unlock_user(unlock_input.strip(), lock_data):
                        st.success(f"✅ Unlocked `{unlock_input.strip()}` successfully.")
                        st.rerun()
                    else:
                        st.warning("User ID / IP / Socket ID not found in lock file.")
                else:
                    st.warning("Please enter a valid User ID, IP, or Socket ID.")

            if st.button("🧹 Clear All Locks"):
                save_lock_data({})
                st.success("✅ All locks cleared.")
                st.rerun()
        elif pwd:
            st.error("❌ Incorrect password.")

# ------------------------
# Lock check
# ------------------------
if is_user_locked(user_id, socket_id, lock_data):
    st.error("⚠ You have already used this Flashmind demo in the past 30 days.")
    st.stop()

# ------------------------
# Access Form
# ------------------------
st.markdown("### 📝 Steps: Complete Access Form, tick, enter the problem and click on run analysis")
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
    unsafe_allow_html=True,
)
try:
    st.link_button("Click here if form didn’t open", form_url)
except Exception:
    st.markdown(f"[Click here if form didn’t open]({form_url})", unsafe_allow_html=True)

if not st.checkbox("✅ I have filled and submitted the access form"):
    st.warning("Please confirm after submitting the form.")
    st.stop()

# ------------------------
# Analysis Runner (patched with admin override)
# ------------------------
# --- Prominent Topic Input ---
st.markdown(
    """
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
    """,
    unsafe_allow_html=True
)

topic = st.text_input("", placeholder="Type your analysis topic here...")


# check if admin override active in this session
if "admin_override" not in st.session_state:
    st.session_state["admin_override"] = False

if st.button("🚀 Run Flashmind Analysis"):
    # reload and check lock unless admin override is active
    lock_data = load_lock_data()
    if not st.session_state["admin_override"] and is_user_locked(user_id, socket_id, lock_data):
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

        # only lock if not overridden by admin
        if not st.session_state["admin_override"]:
            register_user_lock(user_id, socket_id, lock_data)
            st.success("✅ Analysis complete. Demo locked for 30 days.")
            st.rerun()
        else:
            st.success("✅ Analysis complete (admin override — not locked).")



