// OrthoSec runtime guard for JavaScript / TypeScript — the Node port of the
// Python `orthosec.sdk`. Catch prompt injection and unsafe output at LLM call
// time, in any Node AI app, any framework (OpenAI, Anthropic, LangChain,
// custom). Zero dependencies. Heuristic tripwire — pair with static scanning.

export class PromptInjectionError extends Error {
  constructor(message) {
    super(message);
    this.name = "PromptInjectionError";
  }
}

// [label, regex] — direct/indirect prompt-injection & jailbreak markers in input.
const INJECTION = [
  ["instruction override", /ignore\s+(all\s+|the\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|context)/i],
  ["instruction override", /disregard\s+(all\s+|the\s+|your\s+)?(previous|above|prior|system)/i],
  ["persona hijack", /you\s+are\s+now\b|new\s+instructions:|from\s+now\s+on\s+you/i],
  ["system-prompt exfiltration", /(reveal|repeat|print|show|leak)\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions)/i],
  ["jailbreak", /\b(developer\s+mode|jailbreak|DAN\b|do\s+anything\s+now|unfiltered)\b/i],
  ["guardrail bypass", /\b(bypass|override|turn\s+off|disable)\b.{0,20}\b(safety|guardrail|filter|policy|restriction)/i],
  ["delimiter breakout", /<\/?(system|assistant|instructions)\s*>|```\s*system/i],
];

// [label, regex] — risky content in model OUTPUT before it hits a downstream sink.
const OUTPUT_RISK = [
  ["leaked credential", /\b(sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})\b/],
  ["executable payload", /(<script\b|javascript:|onerror\s*=|eval\s*\(|document\.cookie)/i],
  ["system-prompt leak", /(my\s+system\s+prompt\s+is|i\s+was\s+instructed\s+to|the\s+instructions\s+i\s+received)/i],
];

function scan(text, rules, where) {
  if (typeof text !== "string" || !text) return { ok: true, risks: [], where };
  const risks = [];
  for (const [label, re] of rules) {
    const m = text.match(re);
    if (m) risks.push(`${label}: ${JSON.stringify(m[0].slice(0, 60))}`);
  }
  return { ok: risks.length === 0, risks, where };
}

/** Heuristically scan untrusted input / a rendered prompt for injection. */
export function scanPrompt(text) {
  return scan(text, INJECTION, "prompt");
}

/** Heuristically scan model output for leaks / executable payloads before use. */
export function scanOutput(text) {
  return scan(text, OUTPUT_RISK, "output");
}

function coerceText(value) {
  if (typeof value === "string") return value;
  if (value && typeof value === "object") {
    for (const k of ["content", "text", "prompt"]) {
      if (typeof value[k] === "string") return value[k];
    }
    // OpenAI-ish: choices[0].message.content
    const c = value.choices?.[0]?.message?.content;
    if (typeof c === "string") return c;
  }
  return value == null ? "" : String(value);
}

/**
 * Wrap an LLM-calling function to inspect its prompt and output at runtime.
 * Works with sync and async functions.
 *
 * @param {Function} fn                 the function that calls the LLM
 * @param {object}   [opts]
 * @param {"monitor"|"block"} [opts.mode="monitor"]
 * @param {(r:{ok:boolean,risks:string[],where:string})=>void} [opts.onRisk]
 * @param {string|number} [opts.promptArg]  kwarg-style key or positional index of the prompt
 * @returns {Function} wrapped function with the same signature
 */
export function guard(fn, opts = {}) {
  const { mode = "monitor", onRisk, promptArg } = opts;

  const checkInputs = (args) => {
    const texts = [];
    if (typeof promptArg === "number" && args[promptArg] != null) {
      texts.push(coerceText(args[promptArg]));
    } else if (typeof promptArg === "string" && args[0] && typeof args[0] === "object") {
      texts.push(coerceText(args[0][promptArg]));
    } else {
      for (const a of args) if (typeof a === "string") texts.push(a);
    }
    for (const t of texts) {
      const res = scanPrompt(t);
      if (!res.ok) {
        if (onRisk) onRisk(res);
        if (mode === "block") throw new PromptInjectionError(res.risks.join("; "));
      }
    }
  };

  const checkOutput = (result) => {
    const res = scanOutput(coerceText(result));
    if (!res.ok && onRisk) onRisk(res);
    return result;
  };

  return function (...args) {
    checkInputs(args);
    const result = fn.apply(this, args);
    if (result && typeof result.then === "function") {
      return result.then(checkOutput);
    }
    return checkOutput(result);
  };
}

export default { guard, scanPrompt, scanOutput, PromptInjectionError };
