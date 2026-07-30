class Chat {
    void Ask(ChatClient client, System.Collections.Generic.List<object> messages) {
        var options = new ChatCompletionOptions { MaxOutputTokenCount = 256 };
        client.CompleteChat(messages, options);
    }
}
