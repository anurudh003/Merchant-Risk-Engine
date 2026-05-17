# src/ai_analyzer.py

"""
Compliance-Grounded AI Explainability Engine

Purpose:
- Explain WHY a merchant is risky using only verified findings
- Prevent LLM hallucinations
- Support AML / KYB / Compliance analyst workflows
- Generate safe compliance summaries

IMPORTANT:

This module does NOT:
- detect fraud independently
- invent suspicious behavior
- infer unsupported conclusions

This module ONLY:
- explains detected findings from rules.py
- explains scorer.py final decision
- supports analyst review

Correct Architecture:

scraper.py
    ↓
rules.py
    ↓
scorer.py
    ↓
ai_analyzer.py   ← Explainability Layer ONLY
    ↓
alert_engine.py

Run:
    python src/ai_analyzer.py
"""

import requests
import json


# =========================================================
# OLLAMA CONFIG
# =========================================================

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "phi3"


# =========================================================
# BUILD SAFE COMPLIANCE PROMPT
# =========================================================

def build_ai_prompt(
    merchant_url,
    findings,
    scoring_result,
    verification_result
):
    """
    AI receives ONLY verified facts.

    No raw website guessing.
    No hallucination freedom.
    """

    finding_lines = []

    for item in findings:
        finding_lines.append(
            f"- {item.get('finding', 'Unknown finding')} "
            f"({item.get('severity', 'LOW')})"
        )

    findings_text = "\n".join(finding_lines)

    risk_score = scoring_result.get(
        "risk_score",
        0
    )

    risk_rating = scoring_result.get(
        "risk_rating",
        "MEDIUM"
    )

    recommended_action = scoring_result.get(
        "recommended_action",
        "Manual Review"
    )

    verification_score = verification_result.get(
        "verification_score",
        0
    )

    verification_status = verification_result.get(
        "verification_status",
        "UNKNOWN"
    )

    prompt = f"""
You are a senior Merchant Risk Compliance Analyst.

Your role is STRICTLY:

- explain verified findings
- summarize compliance concerns
- support AML / KYB analyst decisions

You MUST NOT:

- invent fraud patterns
- assume hidden behavior
- guess unsupported risks
- speculate beyond provided findings

Merchant URL:
{merchant_url}

Verified Findings:
{findings_text}

Verification:
Score: {verification_score}
Status: {verification_status}

Final Scoring:
Risk Score: {risk_score}
Risk Rating: {risk_rating}
Recommended Action: {recommended_action}

Return STRICTLY in this exact format:

AI Summary:
<short factual compliance summary>

Escalation Justified:
<Yes or No>

Confidence Score:
<number between 0.0 and 1.0>

Analyst Recommendation:
<short compliance action>

Rules:
- Only explain provided findings
- Do not mention assumptions
- Keep summary short
- No hallucinations
"""

    return prompt


# =========================================================
# OLLAMA CALL
# =========================================================

def analyze_with_ollama(prompt):
    """
    Safe local LLM execution
    """

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1
        }
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=180
        )

        if response.status_code != 200:
            return {
                "error": (
                    f"Ollama API failed: "
                    f"{response.status_code}"
                )
            }

        result = response.json()

        return {
            "raw_response": result.get(
                "response",
                ""
            )
        }

    except Exception as e:
        return {
            "error": str(e)
        }


# =========================================================
# PARSE RESPONSE
# =========================================================

def parse_ai_response(raw_text):
    """
    Safe structured parser
    """

    result = {
        "ai_summary": "Unavailable",
        "escalation_justified": False,
        "ai_confidence": 0.50,
        "analyst_recommendation": "Manual Review"
    }

    try:
        lines = raw_text.splitlines()

        for line in lines:
            line = line.strip()

            if line.startswith("AI Summary:"):
                result["ai_summary"] = (
                    line.replace(
                        "AI Summary:",
                        ""
                    ).strip()
                )

            elif line.startswith(
                "Escalation Justified:"
            ):
                value = line.replace(
                    "Escalation Justified:",
                    ""
                ).strip().lower()

                result[
                    "escalation_justified"
                ] = (
                    "yes" in value
                )

            elif line.startswith(
                "Confidence Score:"
            ):
                value = line.replace(
                    "Confidence Score:",
                    ""
                ).strip()

                try:
                    result[
                        "ai_confidence"
                    ] = float(value)
                except:
                    pass

            elif line.startswith(
                "Analyst Recommendation:"
            ):
                result[
                    "analyst_recommendation"
                ] = (
                    line.replace(
                        "Analyst Recommendation:",
                        ""
                    ).strip()
                )

    except Exception:
        pass

    return result


# =========================================================
# MAIN WRAPPER
# =========================================================

def run_ai_analysis(
    merchant_url,
    findings,
    scoring_result,
    verification_result,
    trusted_merchant=False
):
    """
    Main pipeline wrapper

    Skip AI for strong trusted merchants
    """

    if trusted_merchant:
        return {
            "ai_summary":
                "AI skipped due to trusted merchant verification",
            "escalation_justified": False,
            "ai_confidence": 1.0,
            "analyst_recommendation":
                "Proceed with Standard Monitoring"
        }

    print("\nRunning AI compliance analysis...")

    prompt = build_ai_prompt(
        merchant_url,
        findings,
        scoring_result,
        verification_result
    )

    ai_response = analyze_with_ollama(
        prompt
    )

    if "error" in ai_response:
        return {
            "ai_summary":
                f"AI analysis failed: {ai_response['error']}",
            "escalation_justified": False,
            "ai_confidence": 0.0,
            "analyst_recommendation":
                "Manual Review Recommended"
        }

    parsed_result = parse_ai_response(
        ai_response["raw_response"]
    )

    return parsed_result


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":

    sample_findings = [
        {
            "finding": "High-risk domain TLD detected",
            "severity": "HIGH"
        },
        {
            "finding": "No physical address found",
            "severity": "MEDIUM"
        },
        {
            "finding": "Missing About page",
            "severity": "LOW"
        }
    ]

    sample_scoring = {
        "risk_score": 52,
        "risk_rating": "HIGH",
        "recommended_action":
            "Immediate Compliance Investigation Required"
    }

    sample_verification = {
        "verification_score": 71,
        "verification_status": "MODERATE TRUST"
    }

    result = run_ai_analysis(
        merchant_url="https://example.online",
        findings=sample_findings,
        scoring_result=sample_scoring,
        verification_result=sample_verification,
        trusted_merchant=False
    )

    print("\n========== AI ANALYZER RESULT ==========\n")

    print(
        json.dumps(
            result,
            indent=4
        )
    )