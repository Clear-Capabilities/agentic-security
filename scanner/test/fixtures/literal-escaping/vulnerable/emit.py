def emit_assignment(name, text):
    quoted = text.replace("'", "\\'")
    return name + " = '" + quoted + "'"
