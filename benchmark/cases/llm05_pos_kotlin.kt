fun run(model: ChatModel) {
    val out = model.generate(prompt)
    Runtime.getRuntime().exec(out)
}
