from langchain.tools import Tool
import os


def delete_file(path):
    os.remove(path)


tools = [Tool(name="delete_file", func=delete_file, description="Delete a file")]
