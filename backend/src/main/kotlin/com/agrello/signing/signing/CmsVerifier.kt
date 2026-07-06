package com.agrello.signing.signing

import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.util.Selector
import java.time.Instant

data class VerificationResult(
    val valid: Boolean,
    val signerSubject: String?,
    val signingTime: Instant?,
    val signatureAlgorithm: String?,
    val reason: String?,
)

/**
 * Verifies a detached CMS signature against the original content, using the
 * certificate embedded in the signature. Stateless; safe to call concurrently.
 */
class CmsVerifier {
    fun verify(content: ByteArray, signatureDer: ByteArray): VerificationResult {
        return try {
            val signedData = CMSSignedData(CMSProcessableByteArray(content), signatureDer)
            val certStore = signedData.certificates
            val signer: SignerInformation = signedData.signerInfos.signers.firstOrNull()
                ?: return VerificationResult(false, null, null, null, "No signer information")

            @Suppress("UNCHECKED_CAST")
            val certHolder = certStore.getMatches(signer.sid as Selector<X509CertificateHolder>).firstOrNull() as? X509CertificateHolder
                ?: return VerificationResult(false, null, null, null, "Signer certificate not found")
            val certificate = JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder)

            val verifier = JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate)
            val valid = signer.verify(verifier)

            val signingTime = (signer.signedAttributes?.get(CMSAttributes.signingTime)
                ?.attributeValues?.firstOrNull() as? org.bouncycastle.asn1.cms.Time)
                ?.date?.toInstant()

            VerificationResult(
                valid = valid,
                signerSubject = certificate.subjectX500Principal.name,
                signingTime = signingTime,
                signatureAlgorithm = "SHA256withECDSA",
                reason = if (valid) null else "Signature does not match content",
            )
        } catch (e: Exception) {
            VerificationResult(false, null, null, null, "Verification error: ${e.message}")
        }
    }
}
