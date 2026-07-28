public class A {
  String run(ChatClient chatClient) throws Exception {
    String out = chatClient.prompt().call().content();
    Runtime.getRuntime().exec("ls");   // constant, not model output
    return out;
  }
}
