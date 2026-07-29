# register_tool exposes this action to the agent.
register_tool :run do |cmd|
  system(cmd)
end
