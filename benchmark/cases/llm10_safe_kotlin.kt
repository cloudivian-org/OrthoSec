fun ask(client: OpenAIClient) {
    val params = ChatCompletionCreateParams.builder()
        .maxTokens(256)
        .build()
    client.chat().completions().create(params)
}
