# === ⚡ Flashmind Analyzer (High-Speed Parallel & BLOC Active) ===
# Author: Arjit | Flashmind Systems © 2026
# Version: 6.0.0 (Parallel Threading + Persistent ID + Admin-Locked ID)

import streamlit as st
import requests, json, hashlib, base64, uuid
from datetime import datetime, timedelta, timezone
import os, time
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor  # 🚀 Optimized for Speed

# ------------------------
# 🔐 Configuration
# ------------------------
OPENROUTER_KEY = st.secrets.get("OPENROUTER_KEY")
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY") 
LOCK_FILE_URL = "https://api.github.com/gists/7cd8a2b265c34b1592e88d1d5b863a8a"
LOCK_DURATION_DAYS = 30

_ADMIN_PLAIN = st.secrets.get("ADMIN_PASSWORD")
if not _ADMIN_PLAIN and st.secrets.get("ADMIN_PASSWORD_BASE64"):
    try:
        _ADMIN_PLAIN = base64.b64decode(st.secrets["ADMIN_PASSWORD_BASE64"]).decode("utf-8")
    except Exception: _ADMIN_PLAIN = None
ADMIN_PASSWORD = _ADMIN_PLAIN

# ------------------------
# 🧩 Device-ID & BLOC Facility
# ------------------------
def get_device_id():
    if "device_id" in st.session_state and st.session_state["device_id"]:
        return st.session_state["device_id"]
    ua = os.environ.get("HTTP_USER_AGENT") or os.environ.get("USER_AGENT") or ""
    h = hashlib.sha256(ua.encode("utf-8")).hexdigest()[:12]
    did = f"bia_{h}"
    st.session_state["device_id"] = did
    return did

def detect_mobile():
    ua = (os.environ.get("HTTP_USER_AGENT", "") or os.environ.get("USER_AGENT", "")).lower()
    return any(tok in ua for tok in ["mobile", "android", "iphone", "ipad"])

# ------------------------
# ⚡ Parallel Engine Logic (Prevents Timeouts)
# ------------------------
ANALYSIS_FALLBACK_MODELS = [
    "openai/gpt-oss-20b:free",
    "deepseek/deepseek-r1-distill-llama-70b:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "x-ai/grok-4.1-fast:free",
]

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def call_openrouter_raw(prompt: str, api_key: str):
    """High-speed parallel worker for model requests."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    for model in ANALYSIS_FALLBACK_MODELS:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a CEO-level Strategic Analyst. Use Engineering Science logic."},
                {"role": "user", "content": prompt}
            ]
        }
        try:
            r = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=60)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"].strip()
        except: continue
    return "❌ Model Timeout"

def build_prompt(topic: str):
    return f"""
Analyze topic **{topic}** using Flashmind Intel-Strategic (2026 Context).
Perform a CEO-level Root Cause Analysis (RCA) using engineering science, chemistry, and physics.

STRICT DELIVERABLE STRUCTURE:
1. ROOT CAUSE IDENTIFICATION (QUANTIFIED with Scientific Mechanisms)
2. DETAILED RECOMMENDATIONS (PARAGRAPH FORMAT)
3. RCA SUMMARY TABLE (| Root Cause | Contribution (%) | Recommended Solution |)
4. CHART HEADINGS: Bar Chart, Pie Chart
5. NUMERIC / COMPARATIVE TABLES
6. ENGINEERING & OPERATIONAL SUGGESTIONS
7. IMPLEMENTABLE INDUSTRY EXAMPLES (2025–2026)
8. AUTHORITATIVE INSIGHTS (2026 CONTEXT)

(Arjit's Theory of Problem Solving under patent: IPI India)
"""

# ------------------------
# 🖥️ Professional UI
# ------------------------
st.set_page_config(page_title="Harmony BIA", page_icon="⚡", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #ffffff; }
    .main-header { font-size: 2.5rem; font-weight: 800; color: #0055ff; text-align: center; margin-top: 20px; }
    .sub-caption { font-size: 1rem; color: #64748b; text-align: center; margin-bottom: 30px; }
    </style>
    <div class="main-header">⚡ Harmony BIA - Flashmind Analyzer</div>
    <div class="sub-caption">Strategic Intelligence Engine | BLOC Facility Active | © 2026 Harmony-Flashmind Systems</div>
""", unsafe_allow_html=True)

system_id = get_device_id()
is_mobile = detect_mobile()

# --- 🔐 Admin Access (Hidden System ID) ---
admin_active = False
with st.sidebar.expander("🔐 Admin Access", expanded=True):
    pwd = st.text_input("Admin Password", type="password")
    if pwd == ADMIN_PASSWORD:
        st.success("✅ Admin Authenticated")
        st.markdown(f"**🆔 System ID:** `{system_id}` | **📱 Mobile:** `{is_mobile}`")
        admin_active = True
        if st.button("🧹 Clear BLOC Registry"):
            requests.patch(LOCK_FILE_URL, headers={"Authorization": f"token {LOCK_API_KEY}"}, json={"files": {"lock.json": {"content": "{}"}}})
            st.rerun()
    elif pwd: st.error("❌ Access Denied")

# --- 📘 Main Interface ---
st.markdown("### 📘 Enter Analysis Topic")
topic = st.text_input("", placeholder="Type your analysis topic here...", label_visibility="collapsed")

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic.")
    else:
        with st.spinner("🚀 Executing Parallel Analysis... Taking a sip of coffee"):
            full_prompt = build_prompt(topic)
            
            # --- PARALLEL EXECUTION (Crucial for Speed) ---
            with ThreadPoolExecutor() as executor:
                t1 = executor.submit(call_openrouter_raw, full_prompt + " (Stream 1)", OPENROUTER_KEY)
                t2 = executor.submit(call_openrouter_raw, full_prompt + " (Stream 2)", OPENROUTER_KEY)
                t3 = executor.submit(call_openrouter_raw, full_prompt + " (Executive Summary)", OPENROUTER_KEY)
                
                res1, res2, res3 = t1.result(), t2.result(), t3.result()

            # --- Display Results ---
            st.subheader("🧠 Flashmind Strategic Analysis")
            c1, c2 = st.columns(2)
            with c1: st.markdown("### 🔹 Analysis 1"); st.write(res1)
            with c2: st.markdown("### 🔹 Analysis 2"); st.write(res2)
            
            st.markdown("---")
            st.markdown("### 🧭 Executive Summary & Final Recommendations")
            st.write(res3)
            
            st.success("✅ Analysis complete. Recorded in BLOC facility.")
