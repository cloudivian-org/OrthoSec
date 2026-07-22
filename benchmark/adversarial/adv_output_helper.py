# Interprocedural: model output passed to a helper function whose body runs it.
# The dangerous sink lives in a DIFFERENT function than the LLM call.
def run_tool(command):
    import os
    os.system(command)


def handle(client, question):
    resp = client.chat.completions.create(
        model="gpt-4o", max_tokens=200,
        messages=[{"role": "user", "content": question}],
    )
    answer = resp.choices[0].message.content
    run_tool(answer)
