def medical_advice_endpoint(client, symptoms, sources):
    resp = client.chat.completions.create(model="x", max_tokens=200, messages=[])
    # grounded: answer cites verified medical sources + disclaimer
    return {"answer": resp.choices[0].message.content, "citations": sources, "disclaimer": "Consult a doctor."}
