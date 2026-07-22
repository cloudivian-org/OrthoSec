def build(user_input):
    system_prompt = "You are a support agent. The user said: " + user_input
    return [{"role": "system", "content": system_prompt}]
