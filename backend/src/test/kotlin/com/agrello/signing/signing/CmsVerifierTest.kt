package com.agrello.signing.signing

import com.agrello.signing.config.AppConfig
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
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
        assertNotNull(verification.signatureAlgorithm)
        assertTrue(
            verification.signatureAlgorithm!!.contains("ECDSA", ignoreCase = true),
            "Expected signatureAlgorithm to contain 'ECDSA', was: ${verification.signatureAlgorithm}"
        )
    }

    @Test
    fun `tampered content fails verification`() {
        val content = "verify me".toByteArray()
        val result = signer.sign(content)
        val tampered = "verify ME".toByteArray()
        val verification = verifier.verify(tampered, result.signatureDer)
        assertFalse(verification.valid)
        assertNotNull(verification.reason)
    }

    @Test
    fun `malformed signature input returns invalid result without throwing`() {
        val content = "verify me".toByteArray()
        val malformedSig = byteArrayOf(1, 2, 3, 4, 5)
        val verification = verifier.verify(content, malformedSig)
        assertFalse(verification.valid)
        assertNotNull(verification.reason)
    }

    @Test
    fun `empty signature input returns invalid result without throwing`() {
        val content = "verify me".toByteArray()
        val emptySig = byteArrayOf()
        val verification = verifier.verify(content, emptySig)
        assertFalse(verification.valid)
        assertNotNull(verification.reason)
    }
}
