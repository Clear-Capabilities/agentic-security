fun identity(payload: String): String {
    return payload
}

fun emit() {
    val msg = identity("status: ok")
    val f = java.io.File("/tmp/out.log")
    f.writeText(msg)
}
