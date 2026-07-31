// Type definitions for @orthosec/guard

export interface GuardResult {
  ok: boolean;
  risks: string[];
  where: "prompt" | "output";
}

export interface GuardOptions {
  mode?: "monitor" | "block";
  onRisk?: (result: GuardResult) => void;
  promptArg?: string | number;
  /**
   * Escalate to a model backend when one is configured via ORTHOSEC_GUARD_MODEL_URL /
   * ORTHOSEC_OUTPUT_MODEL_URL (opt-in, fail-open, additive). Defaults to true when a
   * backend is set; pass `false` to force the synchronous heuristic-only path.
   */
  model?: boolean;
}

export class PromptInjectionError extends Error {}

/** Synchronous heuristic scan. */
export function scanPrompt(text: string): GuardResult;
export function scanOutput(text: string): GuardResult;

/** Heuristic + optional model escalation (ORTHOSEC_GUARD_MODEL_* / ORTHOSEC_OUTPUT_MODEL_*). */
export function scanPromptAsync(text: string): Promise<GuardResult>;
export function scanOutputAsync(text: string): Promise<GuardResult>;

export function guard<T extends (...args: any[]) => any>(
  fn: T,
  opts?: GuardOptions
): T;

declare const _default: {
  guard: typeof guard;
  scanPrompt: typeof scanPrompt;
  scanOutput: typeof scanOutput;
  scanPromptAsync: typeof scanPromptAsync;
  scanOutputAsync: typeof scanOutputAsync;
  PromptInjectionError: typeof PromptInjectionError;
};
export default _default;
