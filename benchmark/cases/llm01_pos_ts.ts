function h(req: any) {
  const messages = [{ role: "system", content: req.body.instruction }];
  return messages;
}
