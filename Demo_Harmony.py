# === ⚡ Flashmind Analyzer (High-Speed BLOC Edition) ===
# Logic: Parallel Processing + Asynchronous Engine Calls
# Author: Arjit | Flashmind Systems © 2026

import streamlit as st
import requests, json, hashlib, base64, uuid
from datetime import datetime, timedelta, timezone
import os, time
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor # Added for speed

# ------------------------
# 🔐 Configuration
# ------------------------
OPENROUTER_KEY = st.secrets.get("OPENROUTER_KEY")
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY") 
LOCK_FILE_URL = "https://api.github.com/gists/7cd8a2b265c34b1592e88d1d5b863a8a"

_ADMIN_PLAIN = st.secrets.get("ADMIN_PASSWORD")
if not _ADMIN_PLAIN and st.secrets.get("ADMIN_PASSWORD_BASE64"):
    try:
        _ADMIN_PLAIN = base64.b64decode(st.secrets["ADMIN_PASSWORD_BASE64"]).decode("utf-8")
    except Exception: _ADMIN_PLAIN = None
ADMIN_PASSWORD = _ADMIN_PLAIN

# ------------------------
# 🧩 BLOC Facility: Logging & Identification
# ------------------------
def get_device_id():
    if "device_id" in st.session_state: return st.session_state["device_id"]
    ua = os.environ.get("HTTP_USER_AGENT") or os.environ.get("USER_AGENT") or ""
    h = hashlib.sha256(ua.encode("utf-8")).hexdigest()[:12]
    did = f"bia_{h}"
    st.session_state["device_id"] = did
    return did

def detect_mobile():
    ua = (os.environ.get("HTTP_USER_AGENT", "") or os.environ.get("USER_AGENT", "")).lower()
    return any(tok in ua for tok in ["mobile", "android", "iphone", "ipad"])

def record_bloc_activity(system_id, topic, is_mobile, admin_active):
    if not LOCK_API_KEY: return
    headers = {"Authorization": f"token {LOCK_API_KEY}", "Accept": "application/vnd.github+json"}
    try:
        res = requests.get(LOCK_FILE_URL, headers=headers, timeout=5) # Reduced timeout
        data = json.loads(res.json().get("files", {}).get("lock.json", {}).get("content", "{}"))
        entry_id = f"log_{int(time.time())}_{uuid.uuid4().hex[:4]}"
        data[entry_id] = {
            "system_id": system_id,
            "timestamp": datetime.utcnow().isoformat(),
            "topic": topic[:100],
            "mobile": is_mobile,
            "admin_bypass": admin_active
        }
        payload = {"files": {"lock.json": {"content": json.dumps(data, indent=4)}}}
        requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=5)
    except: pass # Silent fail for logs to avoid blocking UI

# ------------------------
# ⚡ Flashmind Engine (Parallel Optimized)
# ------------------------
ANALYSIS_FALLBACK_MODELS = [
    "openai/gpt-oss-20b:free",
    "deepseek/deepseek-r1-distill-llama-70b:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "x-ai/grok-4.1-fast:free",
]

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def call_model(prompt: str, model: str, api_key: str):
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": "CEO-level Strategic Analyst."}, {"role": "user", "content": prompt}]
    }
    try:
        r = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=60)
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"].strip()
    except: return None
    return None

def call_with_fallback(prompt: str, api_key: str):
    for model in ANALYSIS_FALLBACK_MODELS:
        res = call_model(prompt, model, api_key)
        if res: return res
    return "❌ Engine Timeout."

def build_prompt(topic: str):
    return f"""Analyze topic **{topic}** using Flashmind Intel-Strategic. 
STRICT DELIVERABLE:
DELIVERABLE STRUCTURE (STRICT):
1. ROOT CAUSE IDENTIFICATION (QUANTIFIED with Scientific Mechanisms)
2. DETAILED RECOMMENDATIONS (PARAGRAPH FORMAT)
3. RCA SUMMARY TABLE (FOR CHARTING: | Root Cause | Contribution (%) | Recommended Solution |)
4. CHART HEADINGS: Bar Chart: Root Causes Contribution (%), Pie Chart: Root Cause Distribution
5. NUMERIC / COMPARATIVE TABLES
6. DETAILED ENGINEERING & OPERATIONAL SUGGESTIONS
7. IMPLEMENTABLE INDUSTRY EXAMPLES (2025–2026)
8. AUTHORITATIVE INSIGHTS (2026 CONTEXT)
(Arjit's Theory of Problem Solving - Patent: IPI India)"""

# ------------------------
# 🖥️ Professional UI
# ------------------------
st.set_page_config(page_title="Harmony BIA", page_icon="⚡", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #ffffff; }
    .main-header { font-size: 2.2rem; font-weight: 800; color: #0055ff; text-align: center; }
    .sub-caption { font-size: 0.9rem; color: #64748b; text-align: center; margin-bottom: 30px; }
    </style>
    <div class="main-header">⚡ Harmony BIA - Flashmind Analyzer</div>
    <div class="sub-caption">Strategic Intelligence Engine | BLOC Facility Active | © 2026 Harmony-Flashmind Systems</div>
""", unsafe_allow_html=True)

system_id = get_device_id()
is_mobile = detect_mobile()

with st.sidebar.expander("🔐 Admin Access", expanded=True):
    pwd = st.text_input("Admin Password", type="password")
    admin_active = (pwd == ADMIN_PASSWORD)
    if admin_active:
        st.success("Admin Active")
        st.markdown(f"**ID:** `{system_id}` | **Mob:** `{is_mobile}`")

st.markdown("### 📘 Enter Analysis Topic")
topic = st.text_input("", placeholder="Topic for RCA...", label_visibility="collapsed")

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Enter a topic.")
    else:
        with st.spinner("🚀 Omnicore Parallel Processing Active..."):
            prompt = build_prompt(topic)
            
            # --- SPEED UP: PARALLEL EXECUTION ---
            with ThreadPoolExecutor() as executor:
                future1 = executor.submit(call_with_fallback, prompt, OPENROUTER_KEY)
                future2 = executor.submit(call_with_fallback, prompt + "\nProvide Executive Summary only.", OPENROUTER_KEY)
                
                analysis_1 = future1.result()
                summary_final = future2.result()

            st.subheader("🧠 Flashmind Strategic Analysis")
            st.markdown(analysis_1)
            st.markdown("---")
            st.subheader("🧭 Executive Summary")
            st.markdown(summary_final)
            
            # Record BLOC in separate thread to avoid UI lag
            executor.submit(record_bloc_activity, system_id, topic, is_mobile, admin_active)
            st.success("✅ Complete.")
