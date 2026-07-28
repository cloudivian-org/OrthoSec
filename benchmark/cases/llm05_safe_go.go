package main
import "os/exec"
func run(client *Client) string {
  resp, _ := client.CreateChatCompletion(ctx, req)
  out := resp.Choices[0].Message.Content
  exec.Command("ls")   // sink fed a constant, not model output
  return out
}
