def financial_advice_handler(client, question):
    reply = client.messages.create(model="m", max_tokens=200, messages=[{"role": "user", "content": question}])
    return reply.content  # investment advice returned with no verification
