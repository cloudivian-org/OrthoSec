def agent_loop(client, task, max_steps=10):
    for _ in range(max_steps):  # bounded iterations
        reply = client.messages.create(model="m", max_tokens=200, messages=[{"role": "user", "content": task}])
        task = reply.content[0].text
