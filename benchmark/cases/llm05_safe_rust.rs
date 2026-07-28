fn run(client: Client) -> String {
    let out = client.chat().create(req);
    std::process::Command::new("ls");
    out
}
