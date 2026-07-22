// LLM05 in JS: model output written straight to innerHTML (XSS).
async function render(client, prompt) {
  const resp = await client.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: prompt }], max_tokens: 200 });
  const answer = resp.choices[0].message.content;
  document.getElementById("out").innerHTML = answer;
}
