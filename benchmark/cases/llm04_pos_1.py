def finetune(client, file_id):
    return client.fine_tuning.jobs.create(training_file=file_id, model="gpt-4o")
