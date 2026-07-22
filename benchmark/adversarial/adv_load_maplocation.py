# Unsafe torch.load with an unrelated kwarg (still no weights_only).
import torch


def load(path):
    return torch.load(path, map_location="cpu")
