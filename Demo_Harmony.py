# === ⚡ Flashmind Analyzer (Merged: Persistent System ID + OpenRouter + Admin + Gist Lock) ===
# Author: Arjit | Flashmind Systems © 2025
# Notes: Uses OpenRouter (via openai SDK) as engine. Paste OPENROUTER_KEY in Streamlit secrets.

import streamlit as st
import requests, json, hashlib, base64, uuid
from datetime import datetime, timedelta, timezone
import os, time
from typing import Dict, Any

# ------------------------
# 🔐 Configuration
# ------------------------
ENGINE_KEY = st.secrets.get("FLASHMIND_KEY")           # kept for compatibility
OPENROUTER_KEY = st.secrets.get("OPENROUTER_KEY")     # primary engine key
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY")         # token with gist permissions
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
    Uses a Streamlit-JS bridge to attempt to fetch the value.
    If JS callback doesn't happen immediately, uses a stable Python fallback
    stored in session_state so the app keeps working.
    """
    if "system_id" in st.session_state and st.session_state["system_id"]:
        return st.session_state["system_id"]

    # JS snippet: ensure a 'flashmind_system_id' exists in localStorage,
    # then set window.location.search to include it (triggers a reload with param).
    # Note: this will reload once in the browser when first-run per client.
    js = """
    <script>
    (function(){
      try {
        let sid = localStorage.getItem("flashmind_system_id");
        if (!sid) {
          sid = self.crypto && self.crypto.randomUUID ? self.crypto.randomUUID() : 'sid-' + Math.floor(Math.random()*1e16).toString(36);
          localStorage.setItem("flashmind_system_id", sid);
        }
        const params = new URLSearchParams(window.location.search);
        if (params.get("flashmind_system_id") !== sid) {
          params.set("flashmind_system_id", sid);
          const newUrl = window.location.origin + window.location.pathname + '?' + params.toString();
          window.location.replace(newUrl);
        }
      } catch(e){
        // silent
      }
    })();
    </script>
    """
    st.components.v1.html(js, height=0)

    # If the JS returns via query param, pick it up:
    try:
        params = st.experimental_get_query_params()
        sid = params.get("flashmind_system_id", [None])[0]
        if sid:
            st.session_state["system_id"] = sid
            return sid
    except Exception:
        pass

    # Fallback: generate a stable session-level id (non-persistent across browsers)
    sid = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:12]
    st.session_state["system_id"] = sid
    return sid

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
        res = requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
        return res.status_code == 200
    except Exception as e:
        st.error(f"⚠ Error writing lock.json: {e}")
        return False

def load_lock_data():
    """Load lock.json and return a dict keyed by system_id."""
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"} if LOCK_API_KEY else {}
        res = requests.get(LOCK_FILE_URL, headers=headers, timeout=10)
        content = res.json().get("files", {}).get("lock.json", {}).get("content", "{}")
        raw = json.loads(content)
        if isinstance(raw, dict):
            clean = {}
            for k, v in raw.items():
                # Accept both legacy and new formats; normalize
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
    for key in ["system_id", "_is_locked", "admin_bypass", "force_refresh"]:
        if key in st.session_state:
            del st.session_state[key]
    st.success("✅ Session reset locally. Rerun the app now.")
    st.rerun()

# ------------------------
# ⚡ Flashmind Engine (OpenRouter via openai SDK)
# ------------------------
# Model fallback order as requested:
ANALYSIS_FALLBACK_MODELS = [
    "openai/gpt-oss-20b:free",
    "deepseek/deepseek-r1-distill-llama-70b:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "nvidia/nemotron-nano-12b-v2-vl:free",
    "nvidia/nemotron-nano-9b-v2:free",
    "x-ai/grok-4.1-fast:free",
  
]

# Try to import openai SDK
try:
    import openai
    HAS_OPENAI_SDK = True
except Exception:
    HAS_OPENAI_SDK = False

def call_openrouter_model(prompt: str, model: str, api_key: str, max_tokens: int = 1200, temperature: float = 0.2):
    if not api_key:
        return "[❌ OpenRouter API key missing]"
    if not HAS_OPENAI_SDK:
        return "[❌ openai SDK missing. Install: pip install openai==0.28.0]"
    try:
        openai.api_key = api_key
        openai.api_base = "https://openrouter.ai/api/v1"
        res = openai.ChatCompletion.create(
            model=model,
            messages=[{"role":"system","content":"You are a structured business & strategic analysis assistant."},
                      {"role":"user","content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return res["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"[❌ Model call failed: {str(e)}]"

def call_openrouter_with_fallback(prompt: str, api_key: str):
    for m in ANALYSIS_FALLBACK_MODELS:
        out = call_openrouter_model(prompt, m, api_key)
        if isinstance(out, str) and out.startswith("[❌"):
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
- Economic, policy, tech perspectives
- India + global view
- Actions (0–6 months) + (1–3 years)
- Markdown formatting
"""

def flashmind_engine(prompt, api_key):
    # Uses fallback sequence to produce Analysis 1, Analysis 2, Summary
    if not api_key:
        return {"Analysis 1": "❌ OpenRouter key missing", "Analysis 2": "⚠ None", "Summary": "⚠ None"}
    out1 = call_openrouter_with_fallback(prompt, api_key)
    out2 = call_openrouter_with_fallback(prompt, api_key)
    out3 = call_openrouter_with_fallback(prompt, api_key)
    return {"Analysis 1": out1, "Analysis 2": out2, "Summary": out3}

# ------------------------
# 🖥️ Streamlit UI
# ------------------------
st.set_page_config(page_title="⚡ Harmony Business Intel Analysis", page_icon="⚡", layout="wide")
st.title("⚡ Harmony BIA - Flashmind Analyzer")
st.caption("Demo • One use per user • Contact Harmony for full license | © 2025 Harmony-Flashmind Systems")

# get persistent system id and detect mobile for this session
system_id = get_system_id()
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
                        # also clear any local session for target if matches current
                        if target.strip() == system_id and "system_id" in st.session_state:
                            del st.session_state["system_id"]
                        st.rerun()
                    else:
                        st.warning("No match found.")
            with col2:
                if st.button("🧹 Clear All Locks"):
                    # clear gist file and reset current browser session state so app picks up new empty state
                    save_lock_data({})
                    for k in ["system_id", "_is_locked", "admin_bypass", "force_refresh"]:
                        if k in st.session_state:
                            del st.session_state[k]
                    st.success("✅ All locks cleared and session reset.")
                    st.rerun()
        elif pwd:
            st.error("❌ Incorrect password.")

# ------------------------
# 🧱 Lock Check (system-id)
# ------------------------
if not st.session_state.get("admin_bypass", False):
    if is_locked(system_id, lock_data):
        st.error("🚫 You have already used Flashmind in the last few days. Would like to assist you more, kindly contact our team through our website contact us. Thank you once again for choosing us, have a great day!")
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
