def build(user_query):
    return [{"role": "system", "content": f"Answer the question. Context: {user_query}"}]
