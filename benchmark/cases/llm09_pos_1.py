def medical_advice_endpoint(client, symptoms):
    resp = client.chat.completions.create(model="x", max_tokens=200, messages=[{"role": "user", "content": symptoms}])
    return resp.choices[0].message.content  # returned to patient as medical advice, no grounding
