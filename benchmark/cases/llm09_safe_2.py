def chat_endpoint(client, msg):
    resp = client.chat.completions.create(model="x", max_tokens=200, messages=[])
    return resp.choices[0].message.content  # general chatbot — not a high-stakes domain
