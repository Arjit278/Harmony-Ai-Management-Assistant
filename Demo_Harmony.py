# === ⚡ Flashmind Analyzer (High-Speed Parallel Edition) ===
# Logic: ThreadPoolExecutor + Strict 60s Timeout per Stream
# Author: Arjit | Flashmind Systems © 2026

import streamlit as st
import requests, json, hashlib, base64, uuid
from datetime import datetime, timedelta, timezone
import os, time
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor, TimeoutError # Strict Timeout Control

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
# 🧩 Device-ID & Identification
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

# ------------------------
# ⚡ High-Speed Engine (Parallel Optimized)
# ------------------------
ANALYSIS_FALLBACK_MODELS = [
    "openai/gpt-oss-20b:free",
    "deepseek/deepseek-r1-distill-llama-70b:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "x-ai/grok-4.1-fast:free",
]

def call_openrouter_worker(prompt: str, model: str):
    """Internal worker for parallel requests with individual 60s timeout."""
    headers = {"Authorization": f"Bearer {OPENROUTER_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "CEO-level Strategic Analyst (2026). Use scientific RCA logic."},
            {"role": "user", "content": prompt}
        ]
    }
    try:
        # Request-level timeout set to 60s
        r = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=60)
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"].strip()
    except: return None
    return None

def call_with_fallback(prompt: str):
    """Attempts models in order if timeout or failure occurs."""
    for model in ANALYSIS_FALLBACK_MODELS:
        res = call_openrouter_worker(prompt, model)
        if res: return res
    return "❌ Analysis Timed Out (60s Limit Exceeded)"

def build_prompt(topic: str):
    return f"""Analyze topic **{topic}** using Flashmind Intel-Strategic. 
Perform a CEO-level RCA using engineering science, chemistry, and physics.

STRICT DELIVERABLE STRUCTURE:
1. ROOT CAUSE IDENTIFICATION (QUANTIFIED with Scientific Mechanisms)
2. DETAILED RECOMMENDATIONS (PARAGRAPH FORMAT)
3. RCA SUMMARY TABLE (| Root Cause | Contribution (%) | Recommended Solution |)
4. CHART HEADINGS: Bar Chart: Root Causes Contribution (%), Pie Chart: Root Cause Distribution
5. NUMERIC / COMPARATIVE TABLES
6. DETAILED ENGINEERING & OPERATIONAL SUGGESTIONS
7. IMPLEMENTABLE INDUSTRY EXAMPLES (2025–2026)
8. AUTHORITATIVE INSIGHTS (2026 CONTEXT)

(Arjit's Theory of Problem Solving under patent: with IPI India)"""

# ------------------------
# 🖥️ Professional UI Structure
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

# --- Admin Section (Hidden ID Logic) ---
admin_active = False
with st.sidebar.expander("🔐 Admin Access", expanded=True):
    pwd = st.text_input("Admin Password", type="password")
    if pwd == ADMIN_PASSWORD:
        st.success("Admin Authenticated")
        st.markdown(f"**🆔 System ID:** `{system_id}` | **📱 Mobile:** `{is_mobile}`")
        admin_active = True
    elif pwd: st.error("Access Denied")

# --- User Input ---
st.markdown("### 📘 Enter Analysis Topic")
topic = st.text_input("", placeholder="Describe the problem for CEO-level RCA...", label_visibility="collapsed")

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic.")
    else:
        with st.spinner("🚀 Executing Triple-Stream Parallel Analysis (60s Limit)..."):
            full_prompt = build_prompt(topic)
            
            # --- SPEED UP: ASYNCHRONOUS THREADING ---
            # ThreadPoolExecutor ensures all 3 requests start at T=0.
            with ThreadPoolExecutor(max_workers=3) as executor:
                f1 = executor.submit(call_with_fallback, full_prompt + " (Stream 1)")
                f2 = executor.submit(call_with_fallback, full_prompt + " (Stream 2)")
                f3 = executor.submit(call_with_fallback, full_prompt + " (Executive Summary)")
                
                try:
                    # Collect results with a hard 60s gate
                    res1 = f1.result(timeout=60)
                    res2 = f2.result(timeout=60)
                    res3 = f3.result(timeout=60)
                except TimeoutError:
                    res1 = res2 = res3 = "❌ System Timeout: Analysis took longer than 60 seconds."

            # --- Display Results ---
            st.subheader("🧠 Flashmind Strategic Analysis")
            c1, c2 = st.columns(2)
            with c1: st.markdown("### 🔹 Analysis 1"); st.write(res1)
            with c2: st.markdown("### 🔹 Analysis 2"); st.write(res2)
            
            st.markdown("---")
            st.markdown("### 🧭 Executive Summary & Final Recommendations")
            st.write(res3)
            
            st.success("✅ Analysis complete. Use recorded in BLOC facility.")
