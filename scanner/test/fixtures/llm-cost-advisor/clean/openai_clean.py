from openai import OpenAI
import datetime
import logging

client = OpenAI()

# Stable, byte-identical system prefix → caches cleanly.
SYSTEM = "You are a helpful support agent. Follow the policy precisely."

# A timestamp OUTSIDE the prompt (logging) must NOT be flagged.
logging.info(f"request received at {datetime.datetime.now()}")

resp = client.chat.completions.create(
    model="gpt-5-mini",
    reasoning_effort="low",
    messages=[
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": user_q},
    ],
)
