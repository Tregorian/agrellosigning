package com.agrello.signing.signing

import com.agrello.signing.config.AppConfig
import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * Loads the signing identity from a PKCS12 keystore once at construction.
 * The identity is immutable, so the loaded instance is reused across requests.
 */
class KeystoreSigningKeyProvider(config: AppConfig) : SigningKeyProvider {
    private val identity: SigningIdentity

    init {
        val keyStore = KeyStore.getInstance("PKCS12")
        FileInputStream(config.keystorePath).use { stream ->
            keyStore.load(stream, config.keystorePassword.toCharArray())
        }
        val privateKey = keyStore.getKey(config.keyAlias, config.keystorePassword.toCharArray())
            ?: error("No key found for alias '${config.keyAlias}'")
        val certificate = keyStore.getCertificate(config.keyAlias) as? X509Certificate
            ?: error("No X509 certificate found for alias '${config.keyAlias}'")
        identity = SigningIdentity(privateKey as java.security.PrivateKey, certificate)
    }

    override fun identity(): SigningIdentity = identity
}
