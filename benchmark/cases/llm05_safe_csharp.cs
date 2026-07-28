using System.Diagnostics;
class A {
  string Run(ChatClient chat) {
    string outp = chat.CompleteChat(messages).Value.Content[0].Text;
    Process.Start("ls");
    return outp;
  }
}
