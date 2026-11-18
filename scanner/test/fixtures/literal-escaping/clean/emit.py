def emit_assignment(name, text):
    quoted = text.replace("\\", "\\\\").replace("'", "\\'")
    return name + " = '" + quoted + "'"
