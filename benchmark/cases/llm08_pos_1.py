import requests


def index_docs(vectorstore, urls):
    for url in urls:
        page = requests.get(url).text
        vectorstore.add_texts([page])
