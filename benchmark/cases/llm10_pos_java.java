class Chat {
    void ask(OpenAIClient client, Object params) {
        client.chat().completions().create(params);
    }
}
