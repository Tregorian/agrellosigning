package com.agrello.signing

import com.agrello.signing.config.AppConfig
import com.agrello.signing.routes.healthRoutes
import com.agrello.signing.routes.signingRoutes
import com.agrello.signing.signing.CmsSigner
import com.agrello.signing.signing.CmsVerifier
import com.agrello.signing.signing.KeystoreSigningKeyProvider
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.UnsupportedMediaTypeException
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.response.respond
import io.ktor.server.routing.routing
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.LoggerFactory
import java.security.Security

private val appLogger = LoggerFactory.getLogger("com.agrello.signing.Application")

fun main() {
    if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
    val config = AppConfig.fromEnv()
    embeddedServer(Netty, port = config.port, host = "0.0.0.0") { module() }.start(wait = true)
}

fun Application.module() {
    if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
    val config = AppConfig.fromEnv()
    val keyProvider = KeystoreSigningKeyProvider(config)
    val signer = CmsSigner(keyProvider)
    val verifier = CmsVerifier()

    install(StatusPages) {
        // Client errors: bad/missing request content. Safe to echo the message.
        exception<UnsupportedMediaTypeException> { call, cause ->
            appLogger.info("Unsupported media type: {}", cause.message)
            call.respond(HttpStatusCode.UnsupportedMediaType, mapOf("error" to "Expected a multipart/form-data request"))
        }
        exception<BadRequestException> { call, cause ->
            appLogger.info("Bad request: {}", cause.message)
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to (cause.message ?: "Bad request")))
        }
        // Everything else is a server fault: log the stack trace, return a
        // generic 500 without leaking internals to the client.
        exception<Throwable> { call, cause ->
            appLogger.error("Unhandled error", cause)
            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "Internal server error"))
        }
    }
    install(ContentNegotiation) { json() }
    install(CORS) {
        anyHost() // demo only; restrict in production
        allowHeader(io.ktor.http.HttpHeaders.ContentType)
        allowMethod(io.ktor.http.HttpMethod.Post)
    }
    routing {
        healthRoutes()
        signingRoutes(config, signer, verifier, keyProvider)
    }
}
