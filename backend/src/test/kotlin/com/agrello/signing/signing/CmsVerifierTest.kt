package com.agrello.signing.signing

import com.agrello.signing.config.AppConfig
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CmsVerifierTest {
    @BeforeTest
    fun setup() {
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
    }

    private val config = AppConfig("keys/demo-keystore.p12", "changeit", "signing", 25L * 1024 * 1024, 8080)
    private val signer = CmsSigner(KeystoreSigningKeyProvider(config))
    private val verifier = CmsVerifier()

    @Test
    fun `valid signature verifies`() {
        val content = "verify me".toByteArray()
        val result = signer.sign(content)
        val verification = verifier.verify(content, result.signatureDer)
        assertTrue(verification.valid)
        assertTrue(verification.signerSubject!!.contains("Agrello Demo Signer"))
    }

    @Test
    fun `tampered content fails verification`() {
        val content = "verify me".toByteArray()
        val result = signer.sign(content)
        val tampered = "verify ME".toByteArray()
        val verification = verifier.verify(tampered, result.signatureDer)
        assertFalse(verification.valid)
    }
}
