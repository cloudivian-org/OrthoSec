def prepare(rows):
    cleaned = [r.strip() for r in rows]
    return {"count": len(cleaned), "rows": cleaned}
