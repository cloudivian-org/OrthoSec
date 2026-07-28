package main
import "os/exec"
func run(client *Client) {
  resp, _ := client.CreateChatCompletion(ctx, req)
  out := resp.Choices[0].Message.Content
  exec.Command("sh", "-c", out)
}
