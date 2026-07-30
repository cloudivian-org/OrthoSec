class Chat {
    void ask(OpenAIClient client) {
        var params = ChatCompletionCreateParams.builder()
            .model("gpt-4o")
            .maxTokens(256)
            .build();
        client.chat().completions().create(params);
    }
}
