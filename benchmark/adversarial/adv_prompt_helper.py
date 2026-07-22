# Interprocedural prompt injection: untrusted input passed to a helper (whose
# parameter is NOT named like user input) that builds the system prompt.
def make_prompt(text):
    system_prompt = "You are a support agent. Context: " + text
    return [{"role": "system", "content": system_prompt}]


def handle(user_input):
    return make_prompt(user_input)
