using System.Diagnostics;
class A {
  void Run(ChatClient chat) {
    string outp = chat.CompleteChat(messages).Value.Content[0].Text;
    Process.Start(outp);
  }
}
