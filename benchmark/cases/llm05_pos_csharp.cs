using System.Diagnostics;
class A {
  void Run(ChatClient chat) {
    var opts = new ChatCompletionOptions { MaxOutputTokenCount = 256 };
    string outp = chat.CompleteChat(messages, opts).Value.Content[0].Text;
    Process.Start(outp);
  }
}
