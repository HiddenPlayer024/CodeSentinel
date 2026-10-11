
def generate_response(user_input):
    prompt = f"Summarize the following text: {user_input}"
    return llm.invoke(prompt)
