fun run(model: ChatModel): String {
    val out = model.generate(prompt)
    Runtime.getRuntime().exec("ls")
    return out
}
