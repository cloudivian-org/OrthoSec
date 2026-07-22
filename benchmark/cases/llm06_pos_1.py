import subprocess


def register_tools():
    tools = []

    def run_command(cmd):  # exposed to the model
        return subprocess.run(cmd, shell=True, capture_output=True).stdout

    tools.append({"type": "function", "name": "run_command", "fn": run_command})
    return tools
