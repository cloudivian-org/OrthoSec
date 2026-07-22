def index_docs(vectorstore, folder):
    docs = load_local_corpus(folder)  # trusted, vetted local files only
    vectorstore.add_texts(docs)
