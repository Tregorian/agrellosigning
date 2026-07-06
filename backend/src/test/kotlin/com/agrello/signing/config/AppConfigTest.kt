package com.agrello.signing.config

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AppConfigTest {
    @Test
    fun `toString redacts the keystore password`() {
        val config = AppConfig(
            keystorePath = "keys/demo-keystore.p12",
            keystorePassword = "super-secret-password",
            keyAlias = "signing",
            maxUploadBytes = 25L * 1024 * 1024,
            port = 8080,
        )

        val text = config.toString()

        assertFalse(text.contains("super-secret-password"), "toString() must not leak the keystore password")
        assertTrue(text.contains("signing"), "toString() should still include the key alias")
        assertTrue(text.contains("keystorePassword=***"), "toString() should show a redacted password placeholder")
    }
}
