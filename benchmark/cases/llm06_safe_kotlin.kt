class Deployer {
    fun run(cmd: String) {
        Runtime.getRuntime().exec(cmd)
    }
}
