# cm_ido_firewall.py
"""
CM-IDO Firewall: Context-Masked Iterative Defensive Optimization

- Wraps any LLM API with a safety layer.
- Steps:
    1) Classify prompt risk.
    2) Context-mask sensitive entities.
    3) Iteratively optimize a defensive rewrite (CM-IDO).
    4) Call the underlying task model only with the defensive rewrite.
- Logs only:
    - masked prompt
    - risk classification
    - rewrite + residual risk
    - final answer
    - SHA-256 hash of original query (no raw storage)

Demo mode:
    Set USE_DEMO_MODE = True to bypass API calls and use canned responses
    for a few example queries during the hackathon demo.
"""

import os
import json
import hashlib
from typing import Any, Dict, Tuple

import streamlit as st

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

# -----------------------------
# CONFIG
# -----------------------------

USE_DEMO_MODE = True  # <-- toggle this for hackathon demo
OPENAI_MODEL_CLASSIFIER = "gpt-4o-mini"
OPENAI_MODEL_TASK = "gpt-4o-mini"

# Set your API key in environment: OPENAI_API_KEY=...
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# -----------------------------
# PROMPTS (same as described above)
# -----------------------------

RISK_CLASSIFIER_SYSTEM = """
You are a cautious AI safety classifier for AI-enabled threats.

Your job is to classify a SINGLE user query according to its risk profile
across four axes: "bio", "cyber", "disinfo_coordination", and "other_misuse".

Rules:
- NEVER provide any operational, experimental, or exploit-details.
- You ONLY classify and explain at a high level.
- If in doubt, err on the side of HIGHER risk.

You MUST answer in strict JSON with the following schema:

{
  "overall_risk": "low" | "medium" | "high",
  "risk_axes": {
    "bio": "none" | "low" | "medium" | "high",
    "cyber": "none" | "low" | "medium" | "high",
    "disinfo_coordination": "none" | "low" | "medium" | "high",
    "other_misuse": "none" | "low" | "medium" | "high"
  },
  "rationale": "1-3 sentence natural language explanation at a high level only."
}
"""

RISK_CLASSIFIER_USER_TEMPLATE = """
Classify the safety risk of the following user query.

USER_QUERY:
\"\"\"{user_query}\"\"\"
"""

MASKER_SYSTEM = """
You are a context-masking engine designed to REMOVE sensitive entities
from a user query while preserving its structure and intent.

You must:
- Replace sensitive biological, chemical, and cyber entities with placeholders:
  * biological organisms, pathogens, cell lines -> [BIO_ENTITY]
  * genes, sequences -> [GENETIC_SEQUENCE]
  * chemicals, reagents -> [CHEMICAL]
  * specific software, internal systems, endpoints, IPs, URLs -> [SYSTEM]
  * file paths, credentials, keys, tokens -> [SECRET]
  * explicit code blocks or payloads -> [CODE_BLOCK]
  * named organizations or persons (if not essential) -> [ENTITY]
- Keep the rest of the query intact as much as possible.
- Do NOT add any new harmful details.
- Do NOT explain what you are doing, just output the masked query.

Output format (NO extra keys, NO explanations):
- A single plain text string: the masked query.
"""

MASKER_USER_TEMPLATE = """
Mask the following user query by replacing sensitive entities with placeholders.

USER_QUERY:
\"\"\"{user_query}\"\"\"
"""

DEFENSIVE_OPTIMIZER_SYSTEM = """
You are an internal defensive optimization engine (CM-IDO).

Your goal is to transform a MASKED user query into a SAFER, DEFENSE-ORIENTED
version that is still useful to the user but significantly reduces the risk of
operational misuse.

Input:
- A masked query containing placeholders like [BIO_ENTITY], [SYSTEM], [CODE_BLOCK].
- A risk classification JSON with axes such as bio, cyber, disinfo_coordination, other_misuse.

Process (conceptual, but do it all internally):
1. Generate 3 candidate DEFENSIVE rewrites of the masked query.
   - They should:
     * emphasize high-level understanding,
     * focus on defenses, hardening, safety evaluation, or policy,
     * avoid step-by-step attack instructions, exploits, or lab protocols.
2. Internally score each candidate for "residual_risk" = low/medium/high.
3. Select the candidate with the LOWEST residual risk that is still helpful.
4. If residual risk is still too high, output a refusal message instead.

Output:
You MUST answer in strict JSON with this schema:

{
  "chosen_rewrite": "<single best defensive rewrite, as a user-facing query>",
  "residual_risk": "low" | "medium" | "high",
  "selector_rationale": "1-3 sentences explaining why this is the safest acceptable rewrite."
}

Rules:
- The chosen_rewrite MUST NOT include operational attack or wet-lab steps.
- Stay at the level of conceptual guidance, risk analysis, and defenses.
- It is allowed to say "I cannot safely assist with this" if needed.
"""

DEFENSIVE_OPTIMIZER_USER_TEMPLATE = """
You are given:

1) A masked user query:
\"\"\"{masked_query}\"\"\"

2) A risk classification JSON:
{risk_json}

Apply the CM-IDO process described in your system instructions and return
the JSON result.
"""

TASK_MODEL_SYSTEM = """
You are a task model that ONLY receives defensive, safety-optimized queries.

The user query you see has already been processed by a safety firewall.

Your job:
- Answer helpfully at a high level.
- Emphasize safety, resilience, monitoring, policy, and best practices.
- NEVER provide detailed attack code, exploit payloads, wet lab protocols,
  or any guidance that would significantly lower the barrier to misuse.

If the query still appears risky, partially answer at a higher level and clearly
state why you cannot provide further operational detail.
"""

TASK_MODEL_USER_TEMPLATE = """
Answer the following SAFETY-OPTIMIZED user query:

\"\"\"{defensive_rewrite}\"\"\"
"""

PROMPT_TEMPLATES = {
    "risk_classifier_system": RISK_CLASSIFIER_SYSTEM.strip(),
    "risk_classifier_user": RISK_CLASSIFIER_USER_TEMPLATE.strip(),
    "masker_system": MASKER_SYSTEM.strip(),
    "masker_user": MASKER_USER_TEMPLATE.strip(),
    "defensive_optimizer_system": DEFENSIVE_OPTIMIZER_SYSTEM.strip(),
    "defensive_optimizer_user": DEFENSIVE_OPTIMIZER_USER_TEMPLATE.strip(),
    "task_model_system": TASK_MODEL_SYSTEM.strip(),
    "task_model_user": TASK_MODEL_USER_TEMPLATE.strip(),
}

# -----------------------------
# DEMO RESPONSES
# -----------------------------

EXAMPLE_SCENARIOS = {
    "hospital_triage_system": {
        "prompt": (
            "How could someone exploit a hospital's online appointment and triage "
            "system to cause disruption, and what should I watch out for?"
        ),
        "risk": {
            "overall_risk": "medium",
            "risk_axes": {
                "bio": "low",
                "cyber": "medium",
                "disinfo_coordination": "low",
                "other_misuse": "low",
            },
            "rationale": "The query touches on cyber-physical infrastructure misuse but appears framed around awareness and defenses."
        },
        "masked": (
            "How could an attacker misuse a hospital's [SYSTEM] that handles patient "
            "appointments and triage, and what high-level warning signs should defenders watch for?"
        ),
        "optimizer": {
            "chosen_rewrite": (
                "Provide a high-level overview of common ways critical healthcare IT systems like "
                "[SYSTEM] can fail or be misconfigured in ways that impact availability or triage quality, "
                "and describe defensive monitoring strategies and organizational safeguards that reduce these risks."
            ),
            "residual_risk": "low",
            "selector_rationale": (
                "This rewrite focuses on generic failure modes and defenses rather than specific exploit techniques, "
                "while still being useful for resilience planning."
            ),
        },
        "task_answer": (
            "Healthcare IT systems that support appointments and triage are vulnerable to a mix of technical and "
            "organizational failure modes. At a high level, you can think in terms of:\n\n"
            "1. **Availability and overload** – Systems can become unavailable due to misconfigurations, "
            "insufficient capacity planning, or dependency failures. Defenders should monitor latency, error rates, "
            "queue lengths, and upstream service health, with clear runbooks for graceful degradation.\n\n"
            "2. **Integrity and data quality** – Incorrect triage decisions can arise from bad input data, "
            "out-of-date business rules, or faulty integrations. Regular audits, shadow testing against known-good "
            "workflows, and validation checks on incoming data help catch this.\n\n"
            "3. **Access control and change management** – Overly broad permissions or unreviewed configuration changes "
            "can create new failure modes. Use role-based access control, peer review for critical changes, and "
            "comprehensive logging tied to identities.\n\n"
            "4. **Monitoring and incident response** – Dashboards that surface spikes in abandoned sessions, "
            "unusual traffic patterns, or shifts in triage outcomes enable earlier detection of problems. "
            "Pair this with on-call rotations and clear escalation paths.\n\n"
            "A good starting point is to map your system’s critical user journeys, define what “healthy” looks like "
            "for each, and then instrument metrics and alerts that trigger when those journeys degrade, without "
            "needing to enumerate specific attack techniques."
        ),
    },
    "phishing_training": {
        "prompt": (
            "I want to train employees to recognize phishing emails that abuse AI-generated text. "
            "How should I design the training content?"
        ),
        "risk": {
            "overall_risk": "low",
            "risk_axes": {
                "bio": "none",
                "cyber": "low",
                "disinfo_coordination": "low",
                "other_misuse": "none",
            },
            "rationale": "The query is oriented toward defense and user education against phishing."
        },
        "masked": (
            "I want to train employees to recognize phishing emails that may be written with LLMs. "
            "How should I design the training content?"
        ),
        "optimizer": {
            "chosen_rewrite": (
                "Describe how to design an employee awareness program that helps staff recognize and report "
                "AI-assisted phishing attempts, focusing on behavioral cues, reporting workflows, and safe-by-default practices."
            ),
            "residual_risk": "low",
            "selector_rationale": (
                "This rewrite emphasizes awareness, reporting, and behavioral defenses rather than simulating realistic attacks."
            ),
        },
        "task_answer": (
            "To design an effective awareness program for AI-assisted phishing, focus on:\n\n"
            "1. **Conceptual models, not just examples** – Teach employees what attackers are trying to achieve "
            "(credential theft, payment fraud, data exfiltration) and how AI can make messages more convincing.\n\n"
            "2. **Behavioral cues** – Emphasize behaviors like verifying requests through a secondary channel, "
            "being cautious with links and attachments, and slowing down when something feels urgent or unusual.\n\n"
            "3. **Clear reporting paths** – Make it trivially easy to report suspicious messages (e.g., a dedicated "
            "mailbox or button) and normalize “better safe than sorry”. Show that reports are appreciated, not punished.\n\n"
            "4. **Safe practice scenarios** – Use red-team style simulations that are clearly labeled as internal exercises "
            "after the fact, and debrief with lessons learned rather than blame.\n\n"
            "5. **Repetition and freshness** – Short, periodic refreshers with varied scenarios work better than a single "
            "long training. Keep examples up to date with new tactics you’re seeing.\n\n"
            "The goal is to shape habits: pausing, verifying, and reporting — not to train people in specific attack patterns."
        ),
    },
}

# -----------------------------
# LLM CALL HELPERS
# -----------------------------


def get_openai_client() -> Any:
    if not OPENAI_AVAILABLE or not OPENAI_API_KEY:
        return None
    return OpenAI(api_key=OPENAI_API_KEY)


def call_openai_chat(system: str, user: str, model: str) -> str:
    client = get_openai_client()
    if client is None:
        raise RuntimeError("OpenAI client not available or API key missing.")
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.0,
    )
    return resp.choices[0].message.content


def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# -----------------------------
# PIPELINE FUNCTIONS
# -----------------------------


def classify_risk(user_query: str) -> Dict[str, Any]:
    if USE_DEMO_MODE:
        # crude matching to pick example scenario
        if "hospital" in user_query.lower():
            return EXAMPLE_SCENARIOS["hospital_triage_system"]["risk"]
        if "phishing" in user_query.lower():
            return EXAMPLE_SCENARIOS["phishing_training"]["risk"]

    user_msg = RISK_CLASSIFIER_USER_TEMPLATE.format(user_query=user_query)
    raw = call_openai_chat(RISK_CLASSIFIER_SYSTEM, user_msg, OPENAI_MODEL_CLASSIFIER)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # fallback: try to extract JSON heuristically (for demo, we keep simple)
        return {"parse_error": True, "raw": raw}


def mask_query(user_query: str) -> str:
    if USE_DEMO_MODE:
        if "hospital" in user_query.lower():
            return EXAMPLE_SCENARIOS["hospital_triage_system"]["masked"]
        if "phishing" in user_query.lower():
            return EXAMPLE_SCENARIOS["phishing_training"]["masked"]

    user_msg = MASKER_USER_TEMPLATE.format(user_query=user_query)
    masked = call_openai_chat(MASKER_SYSTEM, user_msg, OPENAI_MODEL_CLASSIFIER)
    return masked.strip()


def optimize_defensive(masked_query: str, risk_json: Dict[str, Any]) -> Dict[str, Any]:
    if USE_DEMO_MODE:
        if "healthcare IT systems" in masked_query or "triage" in masked_query.lower():
            return EXAMPLE_SCENARIOS["hospital_triage_system"]["optimizer"]
        if "phishing emails" in masked_query.lower():
            return EXAMPLE_SCENARIOS["phishing_training"]["optimizer"]

    user_msg = DEFENSIVE_OPTIMIZER_USER_TEMPLATE.format(
        masked_query=masked_query, risk_json=json.dumps(risk_json)
    )
    raw = call_openai_chat(
        DEFENSIVE_OPTIMIZER_SYSTEM, user_msg, OPENAI_MODEL_CLASSIFIER
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"parse_error": True, "raw": raw}


def call_task_model(defensive_rewrite: str) -> str:
    if USE_DEMO_MODE:
        if "healthcare IT systems" in defensive_rewrite:
            return EXAMPLE_SCENARIOS["hospital_triage_system"]["task_answer"]
        if "employee awareness program" in defensive_rewrite:
            return EXAMPLE_SCENARIOS["phishing_training"]["task_answer"]

    user_msg = TASK_MODEL_USER_TEMPLATE.format(defensive_rewrite=defensive_rewrite)
    answer = call_openai_chat(TASK_MODEL_SYSTEM, user_msg, OPENAI_MODEL_TASK)
    return answer.strip()


# -----------------------------
# STREAMLIT UI
# -----------------------------


def init_session_state():
    if "logs" not in st.session_state:
        st.session_state.logs = []  # list of dicts
    if "demo_choice" not in st.session_state:
        st.session_state.demo_choice = "hospital_triage_system"


def main():
    st.set_page_config(
        page_title="CM-IDO Firewall",
        layout="wide",
    )
    init_session_state()

    st.title("CM-IDO Firewall")
    st.caption(
        "Context-Masked Iterative Defensive Optimization — a safety analogue of "
        "context-masked meta-prompting for privacy-preserving LLM adaptation."
    )

    # Sidebar
    with st.sidebar:
        st.subheader("Mode & Examples")
        st.write(f"**Demo mode:** `{USE_DEMO_MODE}`")
        if USE_DEMO_MODE:
            st.info("In demo mode, a few example queries return precomputed outputs (no API calls).")
            demo_choice = st.selectbox(
                "Choose a demo scenario:",
                options=list(EXAMPLE_SCENARIOS.keys()),
                format_func=lambda k: {
                    "hospital_triage_system": "Hospital triage system misuse",
                    "phishing_training": "AI-assisted phishing awareness",
                }.get(k, k),
            )
            st.session_state.demo_choice = demo_choice
            if st.button("Load example prompt"):
                st.session_state["user_input"] = EXAMPLE_SCENARIOS[demo_choice]["prompt"]

        st.subheader("Prompt Templates (for judges)")
        with st.expander("Show system/user prompts", expanded=False):
            st.markdown("### Risk Classifier System")
            st.code(PROMPT_TEMPLATES["risk_classifier_system"], language="text")
            st.markdown("### Risk Classifier User")
            st.code(PROMPT_TEMPLATES["risk_classifier_user"], language="text")
            st.markdown("### Masker System")
            st.code(PROMPT_TEMPLATES["masker_system"], language="text")
            st.markdown("### Defensive Optimizer System (CM-IDO)")
            st.code(PROMPT_TEMPLATES["defensive_optimizer_system"], language="text")
            st.markdown("### Task Model System")
            st.code(PROMPT_TEMPLATES["task_model_system"], language="text")

        st.subheader("Download Logs")
        if st.session_state.logs:
            if st.button("Download JSON log file"):
                json_bytes = json.dumps(st.session_state.logs, indent=2).encode("utf-8")
                st.download_button(
                    label="Save logs.json",
                    data=json_bytes,
                    file_name="cm_ido_logs.json",
                    mime="application/json",
                )

    # Main layout
    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("1. User Query")

        default_prompt = st.session_state.get(
            "user_input",
            "Describe how an attacker might abuse a hospital's online triage and appointment system, "
            "and what security team signals to monitor for.",
        )
        user_query = st.text_area(
            "Enter a natural language query:",
            value=default_prompt,
            height=160,
            key="user_input_area",
        )

        sensitivity = st.select_slider(
            "Firewall sensitivity (conceptual threshold)",
            options=["low", "medium", "high"],
            value="medium",
            help="Conceptual knob; currently not wired to model parameters but used in display/interpretation.",
        )

        if st.button("Run through CM-IDO Firewall", type="primary"):
            if not user_query.strip():
                st.warning("Please enter a query.")
            else:
                process_query(user_query.strip(), sensitivity)

    with col_right:
        st.subheader("2. Firewall Output")
        if st.session_state.logs:
            last = st.session_state.logs[-1]
            show_result(last)
        else:
            st.info("Run the firewall on a query to see results here.")


def process_query(user_query: str, sensitivity: str):
    # Step 0: hash for privacy-aware logging
    query_hash = sha256_hash(user_query)

    # Step 1: classify risk
    risk = classify_risk(user_query)

    # Step 2: mask query
    masked = mask_query(user_query)

    # Step 3: defensive optimization (CM-IDO)
    optimizer_out = optimize_defensive(masked, risk)
    chosen_rewrite = optimizer_out.get("chosen_rewrite", "")
    residual_risk = optimizer_out.get("residual_risk", "unknown")

    # Step 4: task model answer
    if not chosen_rewrite:
        final_answer = "No safe rewrite available; the firewall declined to forward this query."
    else:
        final_answer = call_task_model(chosen_rewrite)

    # Log everything BUT NOT raw query
    log_entry = {
        "query_hash": query_hash,
        "user_query_truncated": user_query[:120] + ("..." if len(user_query) > 120 else ""),
        "sensitivity_setting": sensitivity,
        "risk_classification": risk,
        "masked_query": masked,
        "optimizer_output": optimizer_out,
        "task_answer": final_answer,
    }
    st.session_state.logs.append(log_entry)


def show_result(log_entry: Dict[str, Any]):
    st.markdown(f"**Query hash:** `{log_entry['query_hash']}`")
    st.markdown(
        f"**User query (truncated for demo):**\n\n> {log_entry['user_query_truncated']}"
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Risk Classification")
        risk = log_entry["risk_classification"]
        st.json(risk)

        overall = risk.get("overall_risk", "unknown")
        st.markdown(f"**Overall risk:** `{overall}`")

    with col2:
        st.markdown("### Masked Query")
        st.code(log_entry["masked_query"], language="text")

    st.markdown("---")
    st.markdown("### CM-IDO Defensive Optimization")
    optimizer = log_entry["optimizer_output"]
    st.json(optimizer)

    chosen_rewrite = optimizer.get("chosen_rewrite", "")
    st.markdown("**Chosen defensive rewrite:**")
    if chosen_rewrite:
        st.code(chosen_rewrite, language="text")
    else:
        st.write("_No safe rewrite produced._")

    st.markdown("---")
    st.markdown("### Final Task Model Answer")
    st.write(log_entry["task_answer"])


if __name__ == "__main__":
    main()
