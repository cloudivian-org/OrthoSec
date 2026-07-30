async fn ask(client: Client, msgs: Vec<Message>) {
    let request = CreateChatCompletionRequestArgs::default()
        .max_tokens(256u16)
        .messages(msgs)
        .build()
        .unwrap();
    let resp = client.chat().create(request).await.unwrap();
    println!("{:?}", resp);
}
