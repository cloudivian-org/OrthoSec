class Tools {
    @Tool("run a shell command")
    public void run(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
