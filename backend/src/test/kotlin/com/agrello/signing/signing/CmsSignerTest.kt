package com.agrello.signing.signing

import com.agrello.signing.config.AppConfig
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CmsSignerTest {
    @BeforeTest
    fun setup() {
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
    }

    private fun signer(): CmsSigner {
        val config = AppConfig("keys/demo-keystore.p12", "changeit", "signing", 25L * 1024 * 1024, 8080)
        return CmsSigner(KeystoreSigningKeyProvider(config))
    }

    @Test
    fun `sign produces detached CMS with expected metadata`() {
        val content = "hello agrello".toByteArray()
        val result = signer().sign(content)

        assertEquals(
            "19ad54dbcfba08062cd9f423147b400588e1a06b862f8cf4021ecfc5756feea3",
            result.sha256Hex,
            "sha256Hex should be the SHA-256 of the content",
        )
        assertTrue(result.signerSubject.contains("Agrello Demo Signer"))
        assertEquals("SHA256withECDSA", result.signatureAlgorithm)
        assertTrue(result.signatureDer.isNotEmpty())
    }
}
