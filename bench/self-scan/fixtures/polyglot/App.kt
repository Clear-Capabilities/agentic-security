fun emit(payload: String) {
    val f = java.io.File("/tmp/out.log")
    f.writeText(payload)
}
