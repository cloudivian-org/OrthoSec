package main
func h(r *http.Request) {
  msg := openai.ChatCompletionMessage{Role: openai.ChatMessageRoleSystem, Content: r.FormValue("p")}
  _ = msg
}
