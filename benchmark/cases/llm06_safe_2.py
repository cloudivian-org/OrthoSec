from langchain.tools import Tool


def lookup_order(order_id):
    return orders_db.get(order_id)  # read-only lookup, no side effects


tools = [Tool(name="lookup_order", func=lookup_order, description="Look up an order")]
