package com.agrello.signing.signing

import com.agrello.signing.config.AppConfig
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KeystoreSigningKeyProviderTest {
    @BeforeTest
    fun setup() {
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
    }

    private val config = AppConfig(
        keystorePath = "keys/demo-keystore.p12",
        keystorePassword = "changeit",
        keyAlias = "signing",
        maxUploadBytes = 25L * 1024 * 1024,
        port = 8080,
    )

    @Test
    fun `loads EC identity from keystore`() {
        val identity = KeystoreSigningKeyProvider(config).identity()
        assertEquals("EC", identity.privateKey.algorithm)
        assertTrue(identity.certificate.subjectX500Principal.name.contains("Agrello Demo Signer"))
    }
}
