def run(client)
  out = client.chat(parameters: { max_tokens: 256 }).dig("choices", 0, "message", "content")
  system(out)
end
