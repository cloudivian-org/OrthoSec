public class A {
  void run(ChatClient chatClient) throws Exception {
    String out = chatClient.prompt().call().content();
    Runtime.getRuntime().exec(out);
  }
}
