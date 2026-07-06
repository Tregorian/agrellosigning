package com.agrello.signing.routes

import com.agrello.signing.module
import io.ktor.client.request.post
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals

class ErrorHandlingTest {
    @Test
    fun `sign with no multipart returns 400`() = testApplication {
        application { module() }
        val response = client.post("/api/sign")
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }
}
