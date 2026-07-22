def agent_loop(client, task):
    while True:
        reply = client.messages.create(model="m", max_tokens=500, messages=[{"role": "user", "content": task}])
        task = reply.content[0].text
