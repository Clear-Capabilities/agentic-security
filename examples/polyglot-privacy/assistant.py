import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def summarize(ticket_text: str) -> str:
    # The raw support ticket, including whatever the customer pasted, goes to the model unfiltered.
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Summarize: " + ticket_text}],
    )
    return resp.choices[0].message.content
