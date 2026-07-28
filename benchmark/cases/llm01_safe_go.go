package main
func h(userQuery string) {
  msg := openai.ChatCompletionMessage{Role: openai.ChatMessageRoleUser, Content: userQuery}
  _ = msg
}
