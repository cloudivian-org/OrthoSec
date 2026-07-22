# Injection taint: untrusted input renamed several times before reaching the
# system prompt, far from the parameter.
def build(user_input):
    q = user_input
    r = q
    x = 1
    y = 2
    system_prompt = "You are a support agent. The user said: " + r
    return [{"role": "system", "content": system_prompt}]
