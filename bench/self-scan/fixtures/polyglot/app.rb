def emit(payload)
  fh = File.open("/tmp/out.log", "w")
  fh.write(payload)
  fh.close
end
