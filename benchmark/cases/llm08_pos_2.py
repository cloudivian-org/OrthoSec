from langchain_community.document_loaders import WebBaseLoader
from langchain_community.vectorstores import Chroma


def build_index(url, embeddings):
    docs = WebBaseLoader(url).load()
    return Chroma.from_documents(docs, embeddings)
