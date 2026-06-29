from openai import OpenAI
import datetime

client = OpenAI()

# Cache-killer: timestamp baked into the system prefix → cache never hits.
system = f"You are a helpful support agent. Current time: {datetime.datetime.now()}. Follow the policy."

resp = client.chat.completions.create(
    model="gpt-5.5",
    reasoning_effort="high",
    messages=[
        {"role": "system", "content": system},
        {"role": "user", "content": user_q},
    ],
)
