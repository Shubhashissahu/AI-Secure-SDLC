import openai

def analyze_customer(user_data):
    # ⚠️ VULN: Sensitive Data / PII Exposure in LLM Prompts (CWE-200 / OWASP-LLM06)
    user_prompt = f"Analyze customer financial record for SSN: {user_data['ssn']} with password: {user_data['password']}"
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_prompt}]
    )
    return response
