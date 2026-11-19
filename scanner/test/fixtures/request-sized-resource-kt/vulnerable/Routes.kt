package demo

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.fillRoutes() {
    get("/fill") {
        val n = call.parameters["n"]!!.toInt()
        val bytes = ByteArray(n)
        call.respondText("x".repeat(n) + bytes.size)
    }
}
