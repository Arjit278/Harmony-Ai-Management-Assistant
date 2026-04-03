# ⚡ Flashmind Analyzer — Clean UI + Fallback Engine
# Author: Arjit | Flashmind Systems © 2025

import streamlit as st
import requests, json, hashlib, uuid
from datetime import datetime, timedelta
import os, time

# ------------------------
# CONFIG
# ------------------------
OPENROUTER_KEY = st.secrets.get("OPENROUTER_KEY")
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY")
LOCK_FILE_URL = "https://api.github.com/gists/7cd8a2b265c34b1592e88d1d5b863a8a"
LOCK_DURATION_DAYS = 30
ADMIN_PASSWORD = st.secrets.get("ADMIN_PASSWORD")

# ------------------------
# 🔥 MODEL FALLBACK LIST
# ------------------------
ANALYSIS_FALLBACK_MODELS = [
    "qwen/qwen3-coder:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "nousresearch/hermes-2-pro-llama-3-8b",
    "openai/gpt-oss-20b:free",
    "deepseek/deepseek-r1-distill-llama-70b:free"
]        

# ------------------------
# DEVICE ID
# ------------------------
def get_device_id():
    ua = os.environ.get("HTTP_USER_AGENT", "")
    if not ua:
        ua = str(uuid.uuid4())
    return "bia_" + hashlib.sha256(ua.encode()).hexdigest()[:12]

system_id = get_device_id()

# ------------------------
# LOCK SYSTEM
# ------------------------
def load_lock_data():
    try:
        res = requests.get(LOCK_FILE_URL)
        content = res.json()["files"]["lock.json"]["content"]
        return json.loads(content)
    except:
        return {}

def save_lock_data(data):
    payload = {"files": {"lock.json": {"content": json.dumps(data, indent=2)}}}
    headers = {"Authorization": f"token {LOCK_API_KEY}"}
    requests.patch(LOCK_FILE_URL, headers=headers, json=payload)

def is_locked(system_id, data):
    if system_id not in data:
        return False
    ts = datetime.fromisoformat(data[system_id]["timestamp"])
    return datetime.utcnow() - ts < timedelta(days=LOCK_DURATION_DAYS)

def register_lock(system_id, data):
    data[system_id] = {"timestamp": datetime.utcnow().isoformat()}
    save_lock_data(data)

def unlock(system_id, data):
    if system_id in data:
        del data[system_id]
        save_lock_data(data)

# ------------------------
# 🔥 FLASHMIND PROMPT
# ------------------------
def build_prompt(topic):
    return f"""
Perform a CEO-level Root Cause Analysis for: {topic}

1. Identify root causes with % (total = 100)
2. Use physics, chemistry, engineering logic
3. Provide real-world industry examples (2025–2026)

OUTPUT FORMAT:

### Root Cause Table
| Cause | % | Solution |

### Detailed Explanation

### Recommendations

### Business Impact

### Charts:
- Bar Chart: Root Causes %
- Pie Chart: Distribution
"""

# ------------------------
# 🔥 MODEL CALL WITH FALLBACK
# ------------------------
def call_model_with_fallback(prompt):
    headers = {
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "Content-Type": "application/json"
    }

    for model in ANALYSIS_FALLBACK_MODELS:
        try:
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}]
            }

            r = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=payload,
                stream=stream,
                timeout=60
            )

            if r.status_code != 200:
                continue

            data = r.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content")

            if content:
                return content

        except Exception:
            continue

    return "❌ All models failed"

# ------------------------
# FLASHMIND ENGINE
# ------------------------
def flashmind_engine(prompt):
    return {
        "Analysis 1": call_model_with_fallback(prompt),
        "Analysis 2": call_model_with_fallback(prompt),
        "Summary": call_model_with_fallback(prompt)
    }

# ------------------------
# UI CONFIG
# ------------------------
st.set_page_config(layout="wide")

st.markdown("""
<style>
.main-title {
    text-align:center;
    font-size:30px;
    font-weight:700;
    margin-bottom:25px;
}
.stTextInput input {
    border-radius:12px !important;
    padding:14px !important;
}
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='main-title'>⚡ Flashmind Analyzer powered by Intelligent Patent RC layout </div>", unsafe_allow_html=True)

# ------------------------
# ADMIN PANEL
# ------------------------
lock_data = load_lock_data()

with st.sidebar:
    st.markdown("### 🔐 Admin Panel")

    pwd = st.text_input("Password", type="password")

    if pwd == ADMIN_PASSWORD:
        st.success("Admin Access")

        for sid, val in lock_data.items():
            st.write(f"{sid} | {val['timestamp']}")

        target = st.text_input("System ID")

        if st.button("Unlock User"):
            unlock(target, lock_data)
            st.success("Unlocked")

        if st.button("Clear All"):
            save_lock_data({})
            st.success("All cleared")

# ------------------------
# LOCK CHECK
# ------------------------
if is_locked(system_id, lock_data):
    st.error("🚫 Access restricted. Contact admin.")
    st.stop()

# ------------------------
# MAIN UI
# ------------------------
topic = st.text_input("", placeholder="Enter your analysis topic...")

if st.button("Generate Analysis"):

    if not topic:
        st.warning("Enter a topic")
        st.stop()

    with st.spinner("Running Flashmind Analysis..."):
        prompt = build_prompt(topic)
        result = flashmind_engine(prompt)

    st.markdown("### 🧠 Analysis 1")
    st.write(result["Analysis 1"])

    st.markdown("### 🧠 Analysis 2")
    st.write(result["Analysis 2"])

    st.markdown("### 📊 Summary")
    st.write(result["Summary"])

    register_lock(system_id, lock_data)
