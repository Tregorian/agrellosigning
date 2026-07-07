package com.agrello.signing.signing

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.Time
import org.bouncycastle.asn1.ess.ESSCertIDv2
import org.bouncycastle.asn1.ess.SigningCertificateV2
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Date

// signatureDer is a ByteArray, so the generated data-class equals/hashCode use
// identity rather than content equality. SignatureResult is never compared, so
// that's fine; suppress the inspection rather than hand-roll unused overrides.
@Suppress("ArrayInDataClass")
data class SignatureResult(
    val signatureDer: ByteArray,
    val sha256Hex: String,
    val signerSubject: String,
    val signingTime: Instant,
    val signatureAlgorithm: String,
)

/**
 * Produces a detached CMS/CAdES-BES signature over the given content.
 * Stateless per call: a fresh generator is built each time, so it is safe to
 * invoke concurrently. Signed attributes make it CAdES-BES:
 * content-type, message-digest (added by BC), signing-time, signing-certificate-v2.
 */
class CmsSigner(
    private val keyProvider: SigningKeyProvider,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val signatureAlgorithm = "SHA256withECDSA"

    fun sign(content: ByteArray): SignatureResult {
        val identity = keyProvider.identity()
        val now = clock.instant()

        val signedAttributes = ASN1EncodableVector().apply {
            add(Attribute(CMSAttributes.signingTime, DERSet(Time(Date.from(now)))))
            val certDigest = MessageDigest.getInstance("SHA-256").digest(identity.certificate.encoded)
            val signingCert = SigningCertificateV2(arrayOf(ESSCertIDv2(certDigest)))
            add(Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, DERSet(signingCert)))
        }

        val contentSigner = JcaContentSignerBuilder(signatureAlgorithm)
            .setProvider("BC")
            .build(identity.privateKey)

        val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(
            JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
        )
            .setSignedAttributeGenerator(DefaultSignedAttributeTableGenerator(AttributeTable(signedAttributes)))
            .build(contentSigner, identity.certificate)

        val generator = CMSSignedDataGenerator().apply {
            addSignerInfoGenerator(signerInfoGenerator)
            addCertificates(JcaCertStore(listOf(identity.certificate)))
        }

        // false => detached: the content is not embedded in the signature.
        val signedData = generator.generate(CMSProcessableByteArray(content), false)

        val sha256Hex = MessageDigest.getInstance("SHA-256").digest(content)
            .joinToString("") { "%02x".format(it) }

        return SignatureResult(
            signatureDer = signedData.getEncoded(),
            sha256Hex = sha256Hex,
            signerSubject = identity.certificate.subjectX500Principal.name,
            signingTime = now,
            signatureAlgorithm = signatureAlgorithm,
        )
    }
}
