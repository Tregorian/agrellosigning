package com.agrello.signing.routes

import com.agrello.signing.module
import io.ktor.client.request.forms.MultiPartFormDataContent
import io.ktor.client.request.forms.formData
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SigningRoutesTest {
    @Test
    fun `sign endpoint returns signature metadata`() = testApplication {
        application { module() }
        val response = client.post("/api/sign") {
            setBody(MultiPartFormDataContent(formData {
                append("file", "hello".toByteArray(), Headers.build {
                    append(HttpHeaders.ContentType, ContentType.Application.OctetStream.toString())
                    append(HttpHeaders.ContentDisposition, "filename=\"hello.txt\"")
                })
            }))
        }
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("sha256Hex"))
        assertTrue(body.contains("signatureBase64"))
        assertTrue(body.contains("Agrello Demo Signer"))
    }

    @Test
    fun `certificate endpoint returns PEM`() = testApplication {
        application { module() }
        val response = client.get("/api/certificate")
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("-----BEGIN CERTIFICATE-----"))
        assertTrue(body.contains("-----END CERTIFICATE-----"))
    }
}
