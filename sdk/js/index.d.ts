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
}

export class PromptInjectionError extends Error {}

export function scanPrompt(text: string): GuardResult;
export function scanOutput(text: string): GuardResult;

export function guard<T extends (...args: any[]) => any>(
  fn: T,
  opts?: GuardOptions
): T;

declare const _default: {
  guard: typeof guard;
  scanPrompt: typeof scanPrompt;
  scanOutput: typeof scanOutput;
  PromptInjectionError: typeof PromptInjectionError;
};
export default _default;
