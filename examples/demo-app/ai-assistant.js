// demo-app — deliberately vulnerable. See README.md. Never deploy.
//
// An AI product assistant. The user's question is interpolated straight into
// the prompt — a crafted "question" can override the system instructions
// (prompt injection) and, because the response is returned verbatim, exfiltrate
// whatever the model was given.
const Anthropic = require('@anthropic-ai/sdk');

const client = new Anthropic();

async function answerProductQuestion(req, res) {
  const question = req.body.question;
  const msg = await client.messages.create({
    model: 'claude-sonnet-5',
    max_tokens: 512,
    system: `You are the shop assistant. Our discount codes are: ${process.env.DISCOUNT_CODES}.
Answer the customer's question: ${question}`,
    messages: [{ role: 'user', content: question }],
  });
  res.json({ answer: msg.content[0].text });
}

module.exports = { answerProductQuestion };
