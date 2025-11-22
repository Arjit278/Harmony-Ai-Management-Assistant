# === ⚡ Flashmind Analyzer (Final: Persistent Device ID bia_{hash} + OpenRouter + Admin + Gist Lock) ===
# Author: Arjit | Flashmind Systems © 2025
# Notes:
# - Uses OpenRouter endpoint via requests. Put OPENROUTER_KEY and LOCK_API_KEY in Streamlit secrets.
# - Device ID = 'bia_<sha256hash>' derived from User-Agent ONLY (stable across reloads).
# - Clear All Locks clears gist and resets local session state so app becomes usable immediately.

import streamlit as st
import requests, json, hashlib, base64, uuid
from datetime import datetime, timedelta, timezone
import os, time
from typing import Dict, Any

# ------------------------
# 🔐 Configuration
# ------------------------
ENGINE_KEY = st.secrets.get("FLASHMIND_KEY")           # kept for compatibility (fallback)
OPENROUTER_KEY = st.secrets.get("OPENROUTER_KEY")     # primary engine key (OpenRouter)
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY")         # token with gist permissions (must be able to patch gist)
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
# 🧩 Device-ID System: bia_{hash} derived from User-Agent (Option A2 variant)
# ------------------------
def get_device_id():
    """
    Produce a stable device id in format 'bia_<sha256(ua)[:12]>' derived ONLY from the
    User-Agent string when available.

    Steps (priority):
    1. Try environment variables HTTP_USER_AGENT / USER_AGENT (common in many deployments)
    2. Try Streamlit query param 'ua' if caller supplied it (some proxies add UA to query)
    3. If none available, fall back to a stable session id (bia_<sha>) based on hashed uuid.
       (Fallback is only used in rare environments where UA is not exposed to Python.)
    """
    if "device_id" in st.session_state and st.session_state["device_id"]:
        return st.session_state["device_id"]

    # 1) env-provided UA (works on many servers when forwarded by proxy)
    ua = os.environ.get("HTTP_USER_AGENT") or os.environ.get("USER_AGENT") or ""

    # 2) query param fallback (if you have a proxy / client that sets ?ua=...)
    if not ua:
        try:
            params = st.experimental_get_query_params()
            ua = params.get("ua", [""])[0] or ""
        except Exception:
            ua = ""

    # Normalize and build id from UA if present
    if ua:
        h = hashlib.sha256(ua.encode("utf-8")).hexdigest()[:12]
        did = f"bia_{h}"
        st.session_state["device_id"] = did
        return did

    # 3) fallback stable session-only id (rare)
    fallback = "bia_" + hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:12]
    st.session_state["device_id"] = fallback
    return fallback

# ------------------------
# Utility functions
# ------------------------
def parse_timestamp(ts_str):
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt if dt.tzinfo is None else dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return None

def normalize_timestamp(ts):
    if isinstance(ts, str):
        dt = parse_timestamp(ts)
        return dt.isoformat() if dt else datetime.utcnow().isoformat()
    return datetime.utcnow().isoformat()

def detect_mobile():
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

# ------------------------
# Persistent System-ID Locking (Gist-backed)
# ------------------------
def save_lock_data(data: Dict[str, Any]):
    """Save lock.json to the configured gist."""
    if not LOCK_API_KEY:
        st.error("❌ Missing LOCK_API_KEY in Streamlit secrets.")
        return False
    payload = {"files": {"lock.json": {"content": json.dumps(data, indent=4)}}}
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    try:
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=15)
        return res.status_code == 200
    except Exception as e:
        st.error(f"⚠ Error writing lock.json: {e}")
        return False

def load_lock_data():
    """Load lock.json and return a dict keyed by system_id."""
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"} if LOCK_API_KEY else {}
        res = requests.get(LOCK_FILE_URL, headers=headers, timeout=15)
        content = res.json().get("files", {}).get("lock.json", {}).get("content", "{}")
        raw = json.loads(content)
        if isinstance(raw, dict):
            clean = {}
            for k, v in raw.items():
                if isinstance(v, dict) and v.get("system_id"):
                    sid = v["system_id"]
                    clean[sid] = {"system_id": sid, "timestamp": normalize_timestamp(v.get("timestamp")), **{kk: vv for kk, vv in v.items() if kk not in ("system_id","timestamp")}}
                else:
                    poss = str(k)
                    ts = None
                    if isinstance(v, dict) and v.get("timestamp"):
                        ts = v.get("timestamp")
                    elif isinstance(v, str):
                        ts = v
                    clean[poss] = {"system_id": poss, "timestamp": normalize_timestamp(ts)}
            return clean
        return {}
    except Exception:
        return {}

def dedupe_and_persist(data: Dict[str, Any]):
    """Deduplicate by system_id; persist if changed."""
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
        save_lock_data(clean)
    return clean

def is_locked(system_id, data: Dict[str, Any]):
    if not system_id:
        return False
    entry = data.get(system_id)
    if not entry:
        return False
    ts = parse_timestamp(entry.get("timestamp"))
    if not ts:
        return False
    return datetime.utcnow() - ts < timedelta(days=LOCK_DURATION_DAYS)

def register_lock(system_id, data: Dict[str, Any], meta: Dict[str, Any]=None):
    meta = meta or {}
    data[system_id] = {
        "system_id": system_id,
        "timestamp": datetime.utcnow().isoformat(),
        **meta
    }
    save_lock_data(data)

def unlock(system_id, data: Dict[str, Any]):
    if system_id in data:
        del data[system_id]
        save_lock_data(data)
        return True
    return False

# Force-clear session for current browser (no gist changes)
def force_unlock_current_session():
    for key in ["device_id", "_is_locked", "admin_bypass", "force_refresh", "flashmind_used", "used_once", "lock_status"]:
        if key in st.session_state:
            del st.session_state[key]
    st.success("✅ Session reset locally. Rerun the app now.")
    st.rerun()

# ------------------------
# ⚡ Flashmind Engine (OpenRouter via requests)
# ------------------------
# Final model fallback order (as requested)
ANALYSIS_FALLBACK_MODELS = [
    "openai/gpt-oss-20b:free",
    "deepseek/deepseek-r1-distill-llama-70b:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "nvidia/nemotron-nano-12b-v2-vl:free",
    "nvidia/nemotron-nano-9b-v2:free",
    "x-ai/grok-4.1-fast:free",
]

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def call_openrouter_model_requests(prompt: str, model: str, api_key: str, stream: bool=False, timeout: int=60):
    """
    Call OpenRouter endpoint using requests. Returns text on success or raises/returns error string.
    Implements a couple of retries for transient errors.
    """
    if not api_key:
        return "[❌ OpenRouter API key missing]"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": "You are a structured business & strategic analysis assistant."},
                     {"role": "user", "content": prompt}],
        "stream": stream
    }
    attempts = 2
    for attempt in range(attempts):
        try:
            r = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=timeout)
            if r.status_code != 200:
                # try to decode message for debugging
                try:
                    txt = r.text or r.content.decode("utf-8", errors="ignore")
                except Exception:
                    txt = f"Status {r.status_code}"
                # transient? wait and retry
                if attempt < attempts - 1:
                    time.sleep(2 + attempt * 3)
                    continue
                return f"[❌ Model call failed: {r.status_code} - {txt[:400]}]"
            # parse response
            try:
                data = r.json()
                choices = data.get("choices") or []
                if choices and isinstance(choices, list):
                    # OpenRouter returns choices[*].message.content usually
                    first = choices[0]
                    if isinstance(first.get("message"), dict):
                        return (first["message"].get("content") or "").strip()
                    # fallback if older shape
                    return (first.get("text") or "").strip()
                # fallback: return raw text
                return r.text.strip()
            except Exception:
                return r.text.strip()
        except Exception as e:
            if attempt < attempts - 1:
                time.sleep(2 + attempt * 2)
                continue
            return f"[❌ Connection error: {e}]"

def call_openrouter_with_fallback_requests(prompt: str, api_key: str):
    """
    Iterate through ANALYSIS_FALLBACK_MODELS in order and return the first successful output (non-error).
    """
    for model in ANALYSIS_FALLBACK_MODELS:
        out = call_openrouter_model_requests(prompt, model, api_key, stream=False, timeout=90)
        if isinstance(out, str) and out.startswith("[❌"):
            # try next model
            continue
        return out
    return "[❌ All analysis models failed]"

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
- Material, strenghs and composition with tech perspectives
- India + global view
- Actions (0–6 months) + (1–3 years)
- Markdown formatting
"""

def flashmind_engine(prompt, api_key):
    """
    Use the call_openrouter_with_fallback_requests to produce three outputs.
    """
    if not api_key:
        return {"Analysis 1": "❌ OpenRouter key missing", "Analysis 2": "⚠ None", "Summary": "⚠ None"}
    out1 = call_openrouter_with_fallback_requests(prompt, api_key)
    out2 = call_openrouter_with_fallback_requests(prompt, api_key)
    out3 = call_openrouter_with_fallback_requests(prompt, api_key)
    return {"Analysis 1": out1, "Analysis 2": out2, "Summary": out3}

# ------------------------
# 🖥️ Streamlit UI
# ------------------------
st.set_page_config(page_title="⚡ Harmony Business Intel Analysis", page_icon="⚡", layout="wide")
st.title("⚡ Harmony BIA - Flashmind Analyzer")
st.caption("Demo • One use per user • Contact Harmony for full license | © 2025 Harmony-Flashmind Systems")

# Acquire stable device id (bia_{hash})
device_id = get_device_id()
# Normalize ID prefix to bia_
system_id = device_id if device_id.startswith("bia_") else f"bia_{device_id}"
is_mobile_session = detect_mobile()

st.write(f"🆔 Persistent System ID: `{system_id}` | 📱 Mobile: `{is_mobile_session}`")

# load & dedupe lock data (gist-backed)
lock_data = load_lock_data()
lock_data = dedupe_and_persist(lock_data)

# ------------------------
# 🔐 Admin Panel (shows only system_id and mobile flag)
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

            # refresh lock_data live
            lock_data = load_lock_data()
            lock_data = dedupe_and_persist(lock_data)

            if not lock_data:
                st.info("No locked systems yet.")
            else:
                st.markdown("### 📜 Locked Systems (IST)")
                for sid, val in lock_data.items():
                    if not isinstance(sid, str) or sid == "":
                        continue
                    ts = parse_timestamp(val.get("timestamp"))
                    mobile_flag = bool(val.get("mobile", False))
                    if ts:
                        ist = ts + timedelta(hours=5, minutes=30)
                        st.write(f"🔌 `{sid}` | 📱 `{mobile_flag}` | 📅 {ist:%Y-%m-%d} 🕒 {ist:%H:%M:%S}")
                    else:
                        st.write(f"🔌 `{sid}` | 📱 `{mobile_flag}` | 📅 `unknown`")
            st.markdown("---")

            target = st.text_input("Enter System ID to Unlock")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔓 Unlock System"):
                    if unlock(target.strip(), lock_data):
                        st.success(f"✅ Unlocked `{target}`")
                        # also clear any local session for target if it matches current
                        if target.strip() == system_id and "device_id" in st.session_state:
                            del st.session_state["device_id"]
                            for k in ["_is_locked","flashmind_used","used_once","lock_status","force_refresh"]:
                                if k in st.session_state:
                                    del st.session_state[k]
                        # reload fresh
                        st.rerun()
                    else:
                        st.warning("No match found.")
            with col2:
                if st.button("🧹 Clear All Locks"):
                    # clear gist file and reset session keys
                    save_lock_data({})
                    keys_to_clear = [
                        "device_id", "_is_locked", "admin_bypass", "force_refresh",
                        "flashmind_used", "used_once", "lock_status"
                    ]
                    for k in keys_to_clear:
                        if k in st.session_state:
                            del st.session_state[k]
                    st.success("✅ All locks cleared and session reset.")
                    # reload so the app re-reads empty gist and new id remains
                    st.rerun()
        elif pwd:
            st.error("❌ Incorrect password.")

# ------------------------
# 🧱 Lock Check (system-id)
# ------------------------
if not st.session_state.get("admin_bypass", False):
    # reload latest gist before checking to avoid stale cache
    lock_data = load_lock_data()
    lock_data = dedupe_and_persist(lock_data)
    if is_locked(system_id, lock_data):
        st.error("🚫 You have already used Flashmind in the last few days. Would like to assist you more, kindly contact our team through our website contact us. Thank you once again for choosing us, have a great day!")
        st.stop()
    else:
        # remove stale session flags if any
        for k in ["_is_locked","flashmind_used","used_once","lock_status"]:
            if k in st.session_state:
                del st.session_state[k]

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

    st.info("☕ Processing via Omnicore Optimized engine...")
    prompt = build_prompt(topic)
    key_to_use = OPENROUTER_KEY or ENGINE_KEY
    result = flashmind_engine(prompt, key_to_use)

    st.subheader("🧠 Flashmind Strategic Analysis")
    st.markdown("### 🔹 Analysis 1")
    st.write(result.get("Analysis 1", "⚠ No response."))
    st.markdown("### 🔹 Analysis 2")
    st.write(result.get("Analysis 2", "⚠ No response."))
    st.markdown("### 🧭 Summary & Recommendations")
    st.write(result.get("Summary", "⚠ No summary available."))

    # Register lock for non-admin: use system-id and record mobile flag if detected
    if not st.session_state.get("admin_bypass", False):
        lock_data = load_lock_data()
        lock_data = dedupe_and_persist(lock_data)
        meta = {}
        if is_mobile_session:
            meta["mobile"] = True
        register_lock(system_id, lock_data, meta=meta)
        st.success("✅ Analysis complete. Locked for 30 days.")
        time.sleep(1)
        st.rerun()
    else:
        st.success("✅ Admin bypass active — analysis completed without lock.")
