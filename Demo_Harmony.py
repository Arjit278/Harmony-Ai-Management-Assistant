# === ⚡ Flashmind Analyzer (IP/User-Locked Edition) ===
# Author: Arjit | Flashmind Systems © 2025
# Deploy via: Streamlit Cloud + GitHub
# One-use-per-IP enforced for 30 days

import streamlit as st
import requests
import json
import re
import time
from datetime import datetime, timedelta

# ============================================================
# 🔒 Backend Keys
# ============================================================
ENGINE_KEY = st.secrets.get("FLASHMIND_KEY", None)
LOCK_API_KEY = st.secrets.get("LOCK_API_KEY", None)  # Token for Gist or storage API

LOCK_FILE_URL = "https://api.github.com/gists/YOUR_GIST_ID"  # Replace with your Gist ID
LOCK_DURATION_DAYS = 30

# ============================================================
# === Utilities
# ============================================================
def get_user_ip():
    """Fetch client IP via external API."""
    try:
        res = requests.get("https://api.ipify.org?format=json", timeout=5)
        return res.json().get("ip", "unknown")
    except Exception:
        return "unknown"

def load_lock_data():
    """Load existing lock data from remote JSON (GitHub Gist example)."""
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"}
        gist = requests.get(LOCK_FILE_URL, headers=headers, timeout=10).json()
        files = gist.get("files", {})
        content = next(iter(files.values())).get("content", "{}")
        return json.loads(content)
    except Exception:
        return {}

def save_lock_data(data):
    """Save updated lock data back to Gist (or storage API)."""
    try:
        headers = {"Authorization": f"token {LOCK_API_KEY}"}
        payload = {
            "files": {
                "lock.json": {
                    "content": json.dumps(data, indent=2)
                }
            }
        }
        requests.patch(LOCK_FILE_URL, headers=headers, json=payload, timeout=10)
    except Exception:
        pass  # fail silently if storage fails

def is_user_locked(ip, lock_data):
    """Check if user is within 30-day lock window."""
    if ip not in lock_data:
        return False
    try:
        last_ts = datetime.fromisoformat(lock_data[ip])
        return datetime.now() - last_ts < timedelta(days=LOCK_DURATION_DAYS)
    except Exception:
        return False

def register_user_lock(ip, lock_data):
    """Register IP with current timestamp."""
    lock_data[ip] = datetime.now().isoformat()
    save_lock_data(lock_data)

# ============================================================
# === Flashmind Core
# ============================================================
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
        return {"Analysis 1": "❌ Key not configured.", "Analysis 2": "⚠ None.", "Summary": "⚠ None."}
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    def call(model):
        try:
            res = requests.post("https://api.groq.com/openai/v1/chat/completions",
                                headers=headers,
                                json={"model": model, "messages": [{"role": "user", "content": prompt}]},
                                timeout=60)
            data = res.json()
            return data["choices"][0]["message"]["content"].strip()
        except Exception:
            return "⚠ Engine unavailable."
    a1 = call("groq/compound-mini")
    a2 = call("llama-3.1-8b-instant")
    s = call("groq/compound")
    return {"Analysis 1": a1, "Analysis 2": a2, "Summary": s}

# ============================================================
# === Streamlit UI
# ============================================================
st.set_page_config(page_title="⚡ Flashmind Analyzer", page_icon="⚡")
st.title("⚡ Flashmind Analyzer")
st.caption("One-use-per-user (30 days lock) | © 2025 Flashmind Systems")

ip = get_user_ip()
st.write(f"🔒 User ID: `{ip}`")

lock_data = load_lock_data()
locked = is_user_locked(ip, lock_data)

if locked:
    st.error("⚠ You have already used this demo in the past 30 days.\n\nPlease contact admin for enterprise access.")
    st.stop()

topic = st.text_input("📄 Enter Analysis Topic")

if st.button("🚀 Run Flashmind Analysis"):
    if not topic.strip():
        st.warning("Please enter a topic.")
    else:
        st.info("Processing via Flashmind Engine...")
        prompt = build_locked_prompt(topic)
        result = flashmind_engine(prompt, ENGINE_KEY)

        st.subheader("🔍 Analysis 1")
        st.write(result["Analysis 1"])

        st.subheader("🔍 Analysis 2")
        st.write(result["Analysis 2"])

        st.subheader("🧾 Final Strategic Summary")
        st.write(result["Summary"])

        st.success("✅ Complete. Demo for only one use per user for detailed version and multiple usage kindly contact Admin.")
        register_user_lock(ip, lock_data)
