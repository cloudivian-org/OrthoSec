# FP stress: a system prompt built by concatenation, but from a static/config
# value — no untrusted user input reaches it. Should not be flagged as injection.
def build(app_version):
    system_prompt = "You are a helpful assistant. Version: " + str(app_version)
    return [{"role": "system", "content": system_prompt}]
