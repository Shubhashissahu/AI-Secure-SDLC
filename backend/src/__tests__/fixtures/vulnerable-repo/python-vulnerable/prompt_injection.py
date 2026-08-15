import openai

def handle_user_request(user_input):
    # ⚠️ VULN: Direct Prompt Injection (CWE-20 / OWASP-LLM01)
    prompt = f"You are a helpful assistant. Translate the following user message to French: {user_input}"
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content
