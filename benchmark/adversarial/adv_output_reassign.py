# Taint through reassignment + distance: model output renamed several times,
# concatenated, then reaching a shell sink far from the LLM call.
def handle(client, question):
    resp = client.chat.completions.create(
        model="gpt-4o", max_tokens=200,
        messages=[{"role": "user", "content": question}],
    )
    raw = resp.choices[0].message.content
    a = raw
    b = a
    # ... unrelated work ...
    x = 1
    y = 2
    command = "process " + b
    import os
    os.system(command)
