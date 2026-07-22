from safetensors.torch import load_file


def load_weights(path):
    return load_file(path)
