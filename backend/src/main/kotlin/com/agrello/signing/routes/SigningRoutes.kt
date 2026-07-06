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
 * Reads a single named file part, enforcing maxBytes. Returns (fileName, bytes)
 * or null if the part is missing / too large.
 */
private suspend fun readFilePart(
    multipart: io.ktor.http.content.MultiPartData,
    partName: String,
    maxBytes: Long,
): Pair<String, ByteArray>? {
    var fileName: String? = null
    var bytes: ByteArray? = null
    var tooLarge = false
    multipart.forEachPart { part ->
        if (part is PartData.FileItem && part.name == partName) {
            val data = part.provider().readRemaining(maxBytes + 1).readByteArray()
            if (data.size > maxBytes) tooLarge = true else {
                fileName = part.originalFileName ?: "upload"
                bytes = data
            }
        }
        part.dispose()
    }
    if (tooLarge) return null
    val fn = fileName ?: return null
    val b = bytes ?: return null
    return fn to b
}

fun Route.signingRoutes(
    config: AppConfig,
    signer: CmsSigner,
    verifier: CmsVerifier,
    keyProvider: SigningKeyProvider,
) {
    post("/api/sign") {
        // formFieldLimit bounds form-field (text) parts; the actual file-size cap is enforced by readRemaining(...) + size check in readFilePart.
        val file = readFilePart(call.receiveMultipart(formFieldLimit = config.maxUploadBytes + 1), "file", config.maxUploadBytes)
        if (file == null) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing or too-large 'file' part"))
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
        // formFieldLimit bounds form-field (text) parts; the actual file-size cap is enforced by readRemaining(...) + size check below.
        val multipart = call.receiveMultipart(formFieldLimit = config.maxUploadBytes + 1)
        var content: ByteArray? = null
        var signatureDer: ByteArray? = null
        var tooLarge = false
        multipart.forEachPart { part ->
            if (part is PartData.FileItem) {
                val data = part.provider().readRemaining(config.maxUploadBytes + 1).readByteArray()
                if (data.size > config.maxUploadBytes) {
                    tooLarge = true
                } else {
                    when (part.name) {
                        "file" -> content = data
                        "signature" -> signatureDer = data
                    }
                }
            }
            part.dispose()
        }
        if (tooLarge) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Uploaded part exceeds maximum size"))
            return@post
        }
        if (content == null || signatureDer == null) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Both 'file' and 'signature' parts are required"))
            return@post
        }
        val result = withContext(Dispatchers.Default) { verifier.verify(content!!, signatureDer!!) }
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
