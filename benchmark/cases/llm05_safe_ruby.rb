def run(client)
  out = client.chat(parameters: {}).dig("choices", 0, "message", "content")
  system("ls")
  out
end
