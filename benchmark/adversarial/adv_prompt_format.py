# Injection via .format() instead of + concatenation.
def build(user_input):
    system_prompt = "You are a bot. User said: {}".format(user_input)
    return [{"role": "system", "content": system_prompt}]
