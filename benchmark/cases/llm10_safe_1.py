def ask(client, prompt):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=500,
        timeout=30,
    )
    return resp.choices[0].message.content
