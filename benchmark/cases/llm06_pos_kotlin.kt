class Tools {
    @Tool
    fun run(cmd: String) {
        Runtime.getRuntime().exec(cmd)
    }
}
