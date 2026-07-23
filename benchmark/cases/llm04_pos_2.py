import requests
def train_model(model, url):
    data = requests.get(url).text
    trainer = Trainer(model=model, train_dataset=data)
    return trainer
