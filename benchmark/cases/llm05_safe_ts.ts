import cp from "child_process";
function run(model: any, q: string) {
  const out = model.invoke(q);
  cp.exec("ls -la");   // sink fed a constant, not model output
  return out;
}
