async fn ask(client: Client, request: CreateChatCompletionRequest) {
    let resp = client.chat().create(request).await.unwrap();
    println!("{:?}", resp);
}
