from markupsafe import escape


def render(model_output):
    safe = escape(model_output)  # escaped before rendering
    return f"<div>{safe}</div>"
