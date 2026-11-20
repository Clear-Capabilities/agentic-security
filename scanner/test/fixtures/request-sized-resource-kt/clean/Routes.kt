package demo

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

const val MAX_FILL = 4096

fun Route.fillRoutes() {
    get("/fill") {
        val n = call.parameters["n"]!!.toInt().coerceAtMost(MAX_FILL)
        val bytes = ByteArray(n)
        call.respondText("x".repeat(n) + bytes.size)
    }
}
