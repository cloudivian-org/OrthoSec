def run(client, prompt):
    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}], max_tokens=200)
    answer = resp.choices[0].message.content
    return eval(answer)
