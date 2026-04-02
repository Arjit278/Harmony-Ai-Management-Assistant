# === ⚡ Flashmind Analyzer (BLOC Facility & Admin Only Edition) ===
# Author: Arjit | Flashmind Systems © 2026
# Version: 5.1.0 (Strict CEO-RCA Structure + Admin Hidden ID)

import streamlit as st
import requests, json, hashlib, base64, uuid
from datetime import datetime, timedelta, timezone
import os, time
from typing import Dict, Any

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
        res = requests.get(LOCK_FILE_URL, headers=headers, timeout=10)
        data = json.loads(res.json().get("files", {}).get("lock.json", {}).get("content", "{}"))
    except: data = {}
    entry_id = f"log_{int(time.time())}_{uuid.uuid4().hex[:4]}"
    data[entry_id] = {
        "system_id": system_id,
        "timestamp": datetime.utcnow().isoformat(),
        "topic": topic[:100],
        "mobile": is_mobile,
        "admin_bypass": admin_active
    }
    payload = {"files": {"lock.json": {"content": json.dumps(data, indent=4)}}}
    requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)

# ------------------------
# ⚡ Flashmind Engine (OpenRouter via requests)
# ------------------------
ANALYSIS_FALLBACK_MODELS = [
    "openai/gpt-oss-20b:free",
    "deepseek/deepseek-r1-distill-llama-70b:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "nvidia/nemotron-nano-12b-v2-vl:free",
    "x-ai/grok-4.1-fast:free",
]

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def call_openrouter_model_requests(prompt: str, model: str, api_key: str):
    if not api_key: return "[❌ OpenRouter API key missing]"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a CEO-level Strategic & Technical Analyst."},
            {"role": "user", "content": prompt}
        ]
    }
    try:
        r = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=90)
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"].strip()
    except: pass
    return f"[❌ Model failed: {model}]"

def call_openrouter_with_fallback_requests(prompt: str, api_key: str):
    for model in ANALYSIS_FALLBACK_MODELS:
        out = call_openrouter_model_requests(prompt, model, api_key)
        if not out.startswith("[❌"): return out
    return "[❌ All analysis models failed]"

def get_references(query):
    return [
        f"https://www.brookings.edu/research/{query.replace(' ', '-')}-2025",
        f"https://www.mckinsey.com/{query.replace(' ', '-')}-insights-2025",
        f"https://www.weforum.org/agenda/{query.replace(' ', '-')}-trends",
    ]

def build_prompt(topic: str):
    refs_md = "\n".join([f"- {r}" for r in get_references(topic)])
    return f"""
Analyze topic **{topic}** using Flashmind Intel-Strategic. 
Perform a **CEO-level Root Cause Analysis (RCA)** using **engineering science, chemistry, physics, and real-world evidence**.

{refs_md}

DELIVERABLE STRUCTURE (STRICT):
1. ROOT CAUSE IDENTIFICATION (QUANTIFIED with Scientific Mechanisms)
2. DETAILED RECOMMENDATIONS (PARAGRAPH FORMAT)
3. RCA SUMMARY TABLE (FOR CHARTING: | Root Cause | Contribution (%) | Recommended Solution |)
4. CHART HEADINGS: Bar Chart: Root Causes Contribution (%), Pie Chart: Root Cause Distribution
5. NUMERIC / COMPARATIVE TABLES
6. DETAILED ENGINEERING & OPERATIONAL SUGGESTIONS
7. IMPLEMENTABLE INDUSTRY EXAMPLES (2025–2026)
8. AUTHORITATIVE INSIGHTS (2026 CONTEXT)

(Arjit's Theory of Problem Solving under patent: with IPI India)
"""

def flashmind_engine(prompt, api_key):
    if not api_key: return {"Analysis 1": "❌ Key missing", "Summary": "⚠ None"}
    return {
        "Analysis 1": call_openrouter_with_fallback_requests(prompt, api_key),
        "Summary": call_openrouter_with_fallback_requests(prompt, api_key)
    }

# ------------------------
# 🖥️ Professional UI
# ------------------------
st.set_page_config(page_title="Harmony BIA", page_icon="⚡", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #ffffff; }
    .main-header { font-size: 2.2rem; font-weight: 800; color: #0055ff; text-align: center; margin-bottom: 0px; }
    .sub-caption { font-size: 0.9rem; color: #64748b; text-align: center; margin-bottom: 30px; }
    </style>
    <div class="main-header">⚡ Harmony BIA - Flashmind Analyzer</div>
    <div class="sub-caption">Strategic Intelligence Engine | BLOC Facility Active | © 2026 Harmony-Flashmind Systems</div>
""", unsafe_allow_html=True)

system_id = get_device_id()
is_mobile = detect_mobile()

# --- Admin Section (System ID Hidden Here) ---
admin_bypass = False
with st.sidebar.expander("🔐 Admin Access", expanded=True):
    pwd = st.text_input("Admin Password", type="password")
    if pwd == ADMIN_PASSWORD:
        st.success("Admin Access Granted")
        st.markdown(f"**🆔 System ID:** `{system_id}`")
        st.markdown(f"**📱 Mobile:** `{is_mobile}`")
        admin_bypass = True
        if st.button("🧹 Clear BLOC Registry"):
            requests.patch(LOCK_FILE_URL, headers={"Authorization": f"token {LOCK_API_KEY}"}, json={"files": {"lock.json": {"content": "{}"}}})
            st.rerun()
    elif pwd: st.error("Access Denied")

# --- Topic Input (Main Page) ---
st.markdown("### 📘 Enter Analysis Topic")
topic = st.text_input("", placeholder="Type your strategic analysis topic here...", label_visibility="collapsed")

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic.")
    else:
        with st.spinner("Processing via Omnicore Optimized engine... Take a sip of coffee"):
            prompt = build_prompt(topic)
            result = flashmind_engine(prompt, OPENROUTER_KEY)
            
            st.subheader("🧠 Flashmind Strategic Analysis")
            st.markdown(result["Analysis 1"])
            
            st.markdown("---")
            st.markdown("### 🧭 Executive Summary & Final Recommendations")
            st.markdown(result["Summary"])
            
            record_bloc_activity(system_id, topic, is_mobile, admin_bypass)
            st.success("✅ Analysis complete. Use recorded in BLOC facility.")
