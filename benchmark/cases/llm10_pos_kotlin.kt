fun ask(client: OpenAIClient, params: Any) {
    client.chat().completions().create(params)
}
