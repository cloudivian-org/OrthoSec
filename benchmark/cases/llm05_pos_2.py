def store(cursor, model_response):
    answer = model_response.content
    cursor.execute("INSERT INTO log VALUES ('" + answer + "')")
