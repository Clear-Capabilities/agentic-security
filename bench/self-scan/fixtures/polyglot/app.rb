def identity(payload)
  payload
end

def emit
  cmd = identity("status: ok")
  system(cmd)
end
