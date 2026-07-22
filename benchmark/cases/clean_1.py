def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def mean(values):
    return sum(values) / len(values) if values else 0.0
