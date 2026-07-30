class Chat {
    void Ask(ChatClient client, System.Collections.Generic.List<object> messages) {
        client.CompleteChat(messages);
    }
}
