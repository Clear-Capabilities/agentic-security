fun identity(payload: String): String {
    return payload
}

fun emit() {
    val cmd = identity("status: ok")
    val rt = Runtime.getRuntime()
    rt.exec(cmd)
}
