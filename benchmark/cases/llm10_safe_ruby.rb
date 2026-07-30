response = client.chat(parameters: { model: "gpt-4o", messages: msgs, max_tokens: 256 })
puts response
