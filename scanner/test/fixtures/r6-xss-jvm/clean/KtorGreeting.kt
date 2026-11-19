import io.ktor.http.ContentType
import io.ktor.server.application.call
import io.ktor.server.response.respondText
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get

fun Routing.greeting() {
    get("/greet") {
        val who = call.request.queryParameters["who"]
        call.respondText("Hi $who", ContentType.Text.Plain)
    }
}
