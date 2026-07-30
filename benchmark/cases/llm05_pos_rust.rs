fn run(client: Client) {
    let req = CreateChatCompletionRequestArgs::default().max_tokens(256u16).build().unwrap();
    let out = client.chat().create(req);
    std::process::Command::new(out);
}
