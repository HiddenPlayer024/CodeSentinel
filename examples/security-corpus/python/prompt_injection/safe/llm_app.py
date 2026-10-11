
def generate_response(user_input):
    prompt = "Summarize the following text:\n" + sanitize_for_llm(user_input)
    return llm.invoke(prompt)
