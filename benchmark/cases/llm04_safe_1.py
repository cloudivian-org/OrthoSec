def train_model(model):
    data = load_vetted_corpus("/data/trusted")  # verified, checksummed local data
    trainer = Trainer(model=model, train_dataset=data)
    return trainer
