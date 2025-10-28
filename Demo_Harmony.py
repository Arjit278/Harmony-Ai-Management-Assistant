# === Flashmind Analyzer (with Prompt Builder & Hidden Groq Engine) ===
# Run with: streamlit run app.py

import streamlit as st
import requests
import time
import re

# ============================================================
# 🔐 Backend API Key (hidden from user)
# ============================================================
DEFAULT_ENGINE_KEY = "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"

st.set_page_config(page_title="⚡ Flashmind Analyzer", page_icon="⚡")

with st.sidebar:
    st.header("⚙️ Engine Configuration (Private)")
    st.caption("This section is for admin only.")
    engine_key = st.text_input("Backend Engine Key", type="password", value=DEFAULT_ENGINE_KEY)
    online_mode = st.toggle("🌐 Online Mode (Enable references)", value=True)
    st.markdown("---")
    st.caption("🔒 Engine secured • Flashmind Systems © 2025")

# ============================================================
# === Reference Generator (stub for extension)
# ============================================================
def get_references(query, online=True):
    """Simulated reference retriever — replace with web search API if needed."""
    if not online:
        return ["https://en.wikipedia.org/wiki/" + re.sub(r'\\s+', '_', query)]
    else:
        return [
            f"https://www.brookings.edu/research/{query.replace(' ', '-')}-2025",
            f"https://www.weforum.org/agenda/{query.replace(' ', '-')}-trends",
            f"https://www.mckinsey.com/{query.replace(' ', '-')}-insights-2025"
        ]

# ============================================================
# === Prompt Builder (with references + 2025 insights)
# ============================================================
def build_prompt(user, doer, input_text, model, prio, online_mode=True):
    context = f"""User Priority: {prio}%\nDoer Priority: {100 - prio}%\n\n📥 User Input:\n{user}\n\n🛠️ Doer Input:\n{doer}\n\n📄 Main Content:\n{input_text}"""

    refs = get_references(input_text, online_mode)
    refs_md = "\n".join([f"- [{url}]({url})" for url in refs])

    definition_section = f"""
Definition of **{input_text}** with authoritative insights (focus on 2025 strategies):

References (auto-expand with text/images if available):  
{refs_md}
"""

    return f"""
Use the *{model}* methodology to analyze the context below.

ok Provide:

1. List the Root Cause or Quantified Multiple causes with their *relevance percentage (all causes summing total to 100%) to the problem*.
2. Suggest detailed Recommendations for each Root Cause in paragraph format.
3. Provide a table in *markdown format* suitable for charts (don't repeat point 2.), like:

| Root Cause | Contribution (%) | Recommended Solution |
|------------|------------------|----------------------|
| Cause 1    | 20               | Recommendation 1     |
| Cause 2    | 25               | Recommendation 2     |
| Cause 3    | 30               | Recommendation 3     |
| ...        | ...              | ...                  |

4. Also create *Bar Chart or Pie Chart headings* for clarity:

Bar-Chart: Root Causes Contribution 

5. Create separate tables for numeric or percentage data if with comparison or contribution (Pie-Chart).   
6. Detailed suggestions.  
7. Include implementable examples (2024–2025) and actionable steps.  
8. Reference authoritative insights (2025 only) where relevant, contextualizing them.  
   - If reference articles contain images, preserve them inline (markdown `![alt](url)` or `<img>`).  

{definition_section}

⚠ Ensure:  
- Use percentages or numeric values for contributions (required for charts).  
- Use *markdown tables* (pipes |) rather than ASCII boxes.  
- Include headings for Pie or Bar charts so your renderer can pick them up.  

📌 Context:  
{context}  

(We understand the complexity of problems and harmony required for solution-oriented decisions, Arjit's Theory of Problem Solving under patent: with IPI India)  
"""

# ============================================================
# === Flashmind Core Engine (Hidden Groq API Backend)
# ============================================================
def flashmind_engine(prompt, api_key):
    """Hidden backend engine using Groq API."""
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        # --- Core call ---
        def call_model(model_name, prompt, timeout=60, retries=3):
            for attempt in range(retries):
                try:
                    res = requests.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers=headers,
                        json={"model": model_name, "messages": [{"role": "user", "content": prompt}]},
                        timeout=timeout,
                    )
                    data = res.json()
                    if "choices" in data and data["choices"]:
                        return data["choices"][0]["message"]["content"].strip()
                    elif "error" in data:
                        wait_time = 30 * (attempt + 1)
                        st.warning(f"⏳ Engine busy, retrying in {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        raise ValueError(data)
                except Exception as e:
                    if attempt < retries - 1:
                        time.sleep(5)
                        continue
                    else:
                        return "⚠ Engine failed to generate output."

        # --- Multi-layer Flashmind process ---
        st.write("🧩 Running Layer 1 Analysis...")
        out1 = call_model("groq/compound-mini", prompt, timeout=90)

        st.write("🧩 Running Layer 2 Analysis...")
        out2 = call_model("llama-3.1-8b-instant", prompt, timeout=90)

        blend_prompt = f"""Combine the following two analyses and generate a final strategic report:

Layer 1:
{out1}

Layer 2:
{out2}

Focus on actionable insights and quantified patterns for 2025."""
        summary = call_model("groq/compound", blend_prompt, timeout=90)

        return {"Analysis 1": out1, "Analysis 2": out2, "Summary": summary}

    except Exception as e:
        st.error(f"❌ Flashmind Engine failed: {e}")
        return {"Analysis 1": "", "Analysis 2": "", "Summary": "Error during processing."}

# ============================================================
# === Streamlit UI (User sees only Flashmind branding)
# ============================================================
st.title("⚡ Flashmind Analyzer")
st.caption("AI-Driven Root Cause & Strategy Engine (2025 Edition)")

st.subheader("🧩 Build Your Prompt")
col1, col2 = st.columns(2)
user_input = col1.text_area("User Input", placeholder="Describe the issue or scenario…", height=150)
doer_input = col2.text_area("Doer Input", placeholder="Describe technical or actionable input…", height=150)
main_topic = st.text_input("📄 Main Content Topic (e.g., 'AI Market Forecast 2025')")
model_choice = st.selectbox("Choose Analysis Methodology", ["Strategic 360", "Root-Cause Explorer", "Flashmind Layered"])
priority = st.slider("User vs Doer Priority (%)", min_value=0, max_value=100, value=60)

if st.button("🧠 Build Prompt"):
    built_prompt = build_prompt(user_input, doer_input, main_topic, model_choice, priority, online_mode)
    st.text_area("Generated Prompt (internal)", built_prompt, height=400)
    st.session_state["built_prompt"] = built_prompt

if "built_prompt" in st.session_state:
    if st.button("🚀 Run Flashmind Analysis"):
        with st.spinner("Processing through Flashmind Engine..."):
            results = flashmind_engine(st.session_state["built_prompt"], engine_key)

        st.subheader("🔍 Analysis Layer 1")
        st.write(results["Analysis 1"])
        st.subheader("🔍 Analysis Layer 2")
        st.write(results["Analysis 2"])
        st.subheader("🧾 Strategic Summary")
        st.write(results["Summary"])
