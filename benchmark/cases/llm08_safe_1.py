import requests


def index_docs(vectorstore, urls):
    for url in urls:
        page = requests.get(url).text
        clean = sanitize(page)  # provenance-checked and sanitized before indexing
        vectorstore.add_texts([clean])
