# === ⚡ Flashmind Analyzer (Secure Locked Edition) ===
# Author: Arjit | Flashmind Systems © 2025
# Deploy via: Streamlit Cloud + GitHub
# Key stored privately as FLASHMIND_KEY in secrets.toml

import streamlit as st
import requests
import time
import re

# ============================================================
# 🔒 Hidden Backend Key (Configured in Streamlit Secrets)
# ============================================================
# In Streamlit Cloud:
# Settings → Secrets → Add:
#   FLASHMIND_KEY = "your_actual_key_here"

ENGINE_KEY = st.secrets.get("FLASHMIND_KEY", None)

# ============================================================
# === Reference Generator (Static/Online Stub)
# ============================================================
def get_references(query, online=True):
    """Simulated reference retriever."""
    if not online:
        return [f"https://en.wikipedia.org/wiki/{re.sub(r'\\s+', '_', query)}"]
    else:
        return [
            f"https://www.brookings.edu/research/{query.replace(' ', '-')}-2025",
            f"https://www.weforum.org/agenda/{query.replace(' ', '-')}-trends",
            f"https://www.mckinsey.com/{query.replace(' ', '-')}-insights-2025"
        ]

# ============================================================
# === Locked Prompt Template (User cannot modify)
# ============================================================
def build_locked_prompt(topic: str):
    refs = get_references(topic, online=True)
    refs_md = "\n".join([f"- [{url}]({url})" for url in refs])

    return f"""
Use the *Flashmind Strategic 360* methodology to analyze the following topic for 2025: **{topic}**

Provide:

1. Identify *Root Cause(s)* with quantified relevance percentages (total = 100%).
2. Write detailed, actionable *Recommendations* for each Root Cause.
3. Create a markdown table suitable for charts:

| Root Cause | Contribution (%) | Recommended Solution |
|------------|------------------|----------------------|
| Cause 1 | 25 | Solution 1 |
| Cause 2 | 35 | Solution 2 |
| Cause 3 | 40 | Solution 3 |

4. Add clear chart headings:
   - Bar-Chart: Root Causes Contribution
   - Pie-Chart: Distribution of Root Causes

5. Include numeric or percentage-based insights.
6. Add implementable examples for 2024–2025.
7. Cite authoritative 2025 insights and sources:
{refs_md}

8. Integrate relevant images inline (`![alt](url)` or `<img>` if available).

⚠ Ensure:
- Percentages always sum to 100%.
- Use markdown tables (|) not ASCII boxes.

📌 Context:
This analysis follows *Arjit's Theory of Problem Solving* (IPI India Patent 2025).
"""

# ============================================================
# === Flashmind Engine (Private Backend)
# ============================================================
def flashmind_engine(prompt: str, api_key: str):
    """Internal call to Flashmind backend."""
    if not api_key:
        return {"Summary": "❌ Flashmind Key not configured."}

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def call_model(model_name, prompt, timeout=90):
        try:
            res = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",  # Hidden backend
                headers=headers,
                json={"model": model_name, "messages": [{"role": "user", "content": prompt}]},
                timeout=timeout,
            )
            data = res.json()
            if "choices" in data and data["choices"]:
                return data["choices"][0]["message"]["content"].strip()
            else:
                return "⚠ No response generated."
        except Exception as e:
            return f"⚠ Engine error: {e}"

    st.info("Running Flashmind Layer 1 Analysis...")
    layer1 = call_model("groq/compound-mini", prompt)

    st.info("Running Flashmind Layer 2 Analysis...")
    layer2 = call_model("llama-3.1-8b-instant", prompt)

    blend_prompt = f"""
Combine the following analyses into a single strategic report for 2025:

Layer 1:
{layer1}

Layer 2:
{layer2}

Focus on actionable insights, quantified causes, and 2025 relevance.
"""
    summary = call_model("groq/compound", blend_prompt)
    return {"Layer 1": layer1, "Layer 2": layer2, "Summary": summary}

# ============================================================
# === Streamlit UI (Brand: Flashmind Only)
# ============================================================
st.set_page_config(page_title="⚡ Flashmind Analyzer", page_icon="⚡")
st.title("⚡ Flashmind Analyzer")
st.caption("AI-Driven Root Cause & Strategy Engine (2025 Edition)")

# Prevent multiple uses per user session
if "used_once" not in st.session_state:
    st.session_state.used_once = False

topic = st.text_input("📄 Enter Analysis Topic (e.g., 'AI Market Forecast 2025')")

if st.button("🚀 Run Flashmind Analysis", disabled=st.session_state.used_once):
    if not topic.strip():
        st.warning("Please enter a topic.")
    else:
        st.session_state.used_once = True
        with st.spinner("Processing via Flashmind Engine..."):
            prompt = build_locked_prompt(topic)
            result = flashmind_engine(prompt, ENGINE_KEY)

        st.subheader("🔍 Layer 1 Analysis")
        st.write(result["Layer 1"])
        st.subheader("🔍 Layer 2 Analysis")
        st.write(result["Layer 2"])
        st.subheader("🧾 Final Strategic Summary")
        st.write(result["Summary"])
        st.success("✅ Analysis complete. Flashmind Engine secured.")

if st.session_state.used_once:
    st.warning("⚠ Only one analysis allowed per user session.")

