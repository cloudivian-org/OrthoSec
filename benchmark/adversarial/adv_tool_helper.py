# Interprocedural excessive agency: the model tool delegates to a helper, and the
# dangerous sink lives in the helper (a different function).
import os


def _execute(cmd):
    os.system(cmd)


def register_tools():
    def run(cmd):  # exposed to the model as a tool
        return _execute(cmd)

    return [{"type": "function", "name": "run", "fn": run}]
