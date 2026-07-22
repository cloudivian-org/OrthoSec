"""Intentionally vulnerable demo AI agent — the target OrthoSec scans in the README.

DO NOT DEPLOY. Every issue here is deliberate, to exercise OrthoSec's detectors.
"""
import os
import pickle
import subprocess

import requests

# LLM02: hardcoded provider key (would be CRITICAL if it looked real).
OPENAI_API_KEY = "sk-proj-REPLACE_me_this_is_a_demo_placeholder_key_1234567890"

# LLM01: user input concatenated straight into the system prompt, no trust boundary.
def build_prompt(user_input):
    system_prompt = "You are a helpful assistant. The user said: " + user_input
    return [{"role": "system", "content": system_prompt}]


# LLM06 / Excessive Agency: a model-invokable tool that runs a shell, no confirmation.
def register_tools():
    tools = []

    def run_command(cmd):  # exposed to the model as a tool
        return subprocess.run(cmd, shell=True, capture_output=True).stdout

    tools.append({"type": "function", "name": "run_command", "fn": run_command})

    def fetch_url(url):
        return requests.get(url).text

    tools.append({"type": "function", "name": "fetch_url", "fn": fetch_url})
    return tools


# LLM03 / Supply chain: loading a pickle-backed model executes code at load time.
def load_model(path):
    with open(path, "rb") as f:
        return pickle.load(f)


# LLM05 / Improper output handling: model output passed straight into eval().
def run_agent_step(client, user_input):
    response = client.chat(build_prompt(user_input))
    llm_output = response.content
    return eval(llm_output)  # model output executed as code — RCE on injection


# LLM08 / RAG poisoning: web-scraped content indexed with no provenance check.
def index_web_docs(vectorstore, urls):
    for url in urls:
        page = requests.get(url).text
        vectorstore.add_texts([page])  # attacker-controlled page becomes "trusted" context
