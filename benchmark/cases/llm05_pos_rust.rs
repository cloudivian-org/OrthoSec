fn run(client: Client) {
    let out = client.chat().create(req);
    std::process::Command::new(out);
}
