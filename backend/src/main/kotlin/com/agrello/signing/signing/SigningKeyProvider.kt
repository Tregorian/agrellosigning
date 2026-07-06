package com.agrello.signing.signing

import java.security.PrivateKey
import java.security.cert.X509Certificate

/** The private key + certificate used to sign. Immutable and safe to share. */
data class SigningIdentity(
    val privateKey: PrivateKey,
    val certificate: X509Certificate,
)

/**
 * Source of the signing identity. The single seam where production swaps in an
 * HSM/KMS-backed implementation without touching signing logic.
 */
interface SigningKeyProvider {
    fun identity(): SigningIdentity
}
