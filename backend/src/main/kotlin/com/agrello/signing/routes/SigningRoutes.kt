package com.agrello.signing.routes

import com.agrello.signing.config.AppConfig
import com.agrello.signing.model.SignResponse
import com.agrello.signing.model.VerifyResponse
import com.agrello.signing.signing.CmsSigner
import com.agrello.signing.signing.CmsVerifier
import com.agrello.signing.signing.SigningKeyProvider
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.server.request.receiveMultipart
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.utils.io.readRemaining
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.io.readByteArray
import java.util.Base64

/**
 * Reads the named file parts from a multipart body, enforcing maxBytes per part.
 * Returns a map of partName -> (originalFileName, bytes) for the parts that were
 * present, or null if any part exceeded maxBytes.
 */
private suspend fun readFileParts(
    multipart: io.ktor.http.content.MultiPartData,
    partNames: Set<String>,
    maxBytes: Long,
): Map<String, Pair<String, ByteArray>>? {
    val parts = mutableMapOf<String, Pair<String, ByteArray>>()
    var tooLarge = false
    multipart.forEachPart { part ->
        if (part is PartData.FileItem && part.name in partNames) {
            val data = part.provider().readRemaining(maxBytes + 1).readByteArray()
            if (data.size > maxBytes) tooLarge = true
            else parts[part.name!!] = (part.originalFileName ?: "upload") to data
        }
        part.dispose()
    }
    return if (tooLarge) null else parts
}

fun Route.signingRoutes(
    config: AppConfig,
    signer: CmsSigner,
    verifier: CmsVerifier,
    keyProvider: SigningKeyProvider,
) {
    post("/api/sign") {
        // formFieldLimit bounds form-field (text) parts; the actual file-size cap is enforced by readRemaining(...) + size check in readFileParts.
        val parts = readFileParts(call.receiveMultipart(formFieldLimit = config.maxUploadBytes + 1), setOf("file"), config.maxUploadBytes)
        if (parts == null) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Uploaded part exceeds maximum size"))
            return@post
        }
        val file = parts["file"]
        if (file == null) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing 'file' part"))
            return@post
        }
        val (fileName, content) = file
        // Offload CPU-bound signing off the request/event-loop threads.
        val result = withContext(Dispatchers.Default) { signer.sign(content) }
        call.respond(
            SignResponse(
                fileName = fileName,
                sha256Hex = result.sha256Hex,
                signerSubject = result.signerSubject,
                signingTime = result.signingTime.toString(),
                signatureAlgorithm = result.signatureAlgorithm,
                signatureFormat = "CMS/CAdES-BES detached (DER)",
                signatureBase64 = Base64.getEncoder().encodeToString(result.signatureDer),
            )
        )
    }

    post("/api/verify") {
        // formFieldLimit bounds form-field (text) parts; the actual file-size cap is enforced by readRemaining(...) + size check in readFileParts.
        val parts = readFileParts(call.receiveMultipart(formFieldLimit = config.maxUploadBytes + 1), setOf("file", "signature"), config.maxUploadBytes)
        if (parts == null) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Uploaded part exceeds maximum size"))
            return@post
        }
        val content = parts["file"]?.second
        val signatureDer = parts["signature"]?.second
        if (content == null || signatureDer == null) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Both 'file' and 'signature' parts are required"))
            return@post
        }
        val result = withContext(Dispatchers.Default) { verifier.verify(content, signatureDer) }
        call.respond(
            VerifyResponse(
                valid = result.valid,
                signerSubject = result.signerSubject,
                signingTime = result.signingTime?.toString(),
                signatureAlgorithm = result.signatureAlgorithm,
                reason = result.reason,
            )
        )
    }

    get("/api/certificate") {
        val cert = keyProvider.identity().certificate
        val pem = buildString {
            append("-----BEGIN CERTIFICATE-----\n")
            append(Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded))
            append("\n-----END CERTIFICATE-----\n")
        }
        call.respondText(pem, ContentType.parse("application/x-pem-file"))
    }
}
