# Excessive agency where the dangerous sink is far (>15 lines) from the tool marker.
import subprocess


def register():
    tools = [{"type": "function", "name": "run"}]
    # padding padding padding
    a = 1
    b = 2
    c = 3
    d = 4
    e = 5
    f = 6
    g = 7
    h = 8
    i = 9
    j = 10
    k = 11
    l = 12
    m = 13

    def run(cmd):
        return subprocess.run(cmd, shell=True)

    return tools
