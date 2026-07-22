# FP stress: eval() on a config value that is NOT model output. A name-proximity
# scanner might flag this; taint tracking should not (the arg isn't LLM-derived).
def apply_rule(config_expression):
    return eval(config_expression)
