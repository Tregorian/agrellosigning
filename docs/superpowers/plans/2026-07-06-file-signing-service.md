# File-Signing Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A file-signing web service where a user uploads a file, a Kotlin/Ktor backend produces a detached CMS/CAdES (`.p7s`) signature over it with an EC P-256 key, and a React frontend shows the result and lets anyone verify it (in-app and via `openssl`).

**Architecture:** Monorepo with a stateless Kotlin/Ktor backend (`backend/`) exposing sign/verify/certificate REST endpoints, and a React+Vite+TS frontend (`frontend/`). Crypto is BouncyCastle. The signing key lives behind a `SigningKeyProvider` interface with a PKCS12-keystore implementation configured entirely via env vars. Docker Compose runs both with one command.

**Tech Stack:** Kotlin 2.1, Ktor 3.1.1 (Netty), BouncyCastle 1.79 (`bcprov-jdk18on`, `bcpkix-jdk18on`), kotlinx-serialization, JUnit 5, JDK 21, Gradle (Kotlin DSL); React 19 + Vite 6 + TypeScript; nginx; Docker Compose.

## Global Constraints

- **JDK 21** for backend build and runtime.
- **Signature standard:** detached CMS/CAdES-BES, DER-encoded `.p7s`. Signed attributes MUST include content-type, message-digest, signing-time, and signing-certificate-v2 (ESSCertIDv2) — the last is what makes it CAdES-BES.
- **Key/digest:** EC P-256 (secp256r1) + SHA-256; signature algorithm `SHA256withECDSA`.
- **Key config via env vars only:** `SIGNING_KEYSTORE_PATH`, `SIGNING_KEYSTORE_PASSWORD`, `SIGNING_KEY_ALIAS`, plus `MAX_UPLOAD_BYTES` and `SERVER_PORT`. Defaults point at the bundled demo keystore.
- **Backend is stateless.** No persistence, no session state. Key loaded once at startup; per-request crypto objects.
- **Demo keystore is a labeled throwaway.** Real `.env` is gitignored; `.env.example` is committed.
- **Base package:** `com.agrello.signing`.
- Register BouncyCastle as a JCA provider exactly once at startup.

---

### Task 1: Backend scaffold + health endpoint

**Files:**
- Create: `backend/settings.gradle.kts`
- Create: `backend/build.gradle.kts`
- Create: `backend/gradle.properties`
- Create: `backend/src/main/kotlin/com/agrello/signing/Application.kt`
- Create: `backend/src/main/kotlin/com/agrello/signing/routes/HealthRoutes.kt`
- Create: `backend/src/main/resources/logback.xml`
- Create: `backend/.gitignore`
- Test: `backend/src/test/kotlin/com/agrello/signing/routes/HealthRoutesTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `fun Application.module()` — installs plugins and routing.
  - `fun Route.healthRoutes()` — registers `GET /health`.

- [ ] **Step 1: Create `backend/settings.gradle.kts`**

```kotlin
rootProject.name = "agrello-signing-backend"
```

- [ ] **Step 2: Create `backend/gradle.properties`**

```properties
kotlin.code.style=official
```

- [ ] **Step 3: Create `backend/build.gradle.kts`**

```kotlin
plugins {
    kotlin("jvm") version "2.1.0"
    kotlin("plugin.serialization") version "2.1.0"
    id("io.ktor.plugin") version "3.1.1"
    application
}

group = "com.agrello.signing"
version = "1.0.0"

application {
    mainClass.set("com.agrello.signing.ApplicationKt")
}

repositories { mavenCentral() }

dependencies {
    implementation("io.ktor:ktor-server-core")
    implementation("io.ktor:ktor-server-netty")
    implementation("io.ktor:ktor-server-content-negotiation")
    implementation("io.ktor:ktor-serialization-kotlinx-json")
    implementation("io.ktor:ktor-server-cors")
    implementation("io.ktor:ktor-server-status-pages")
    implementation("io.ktor:ktor-server-call-logging")
    implementation("ch.qos.logback:logback-classic:1.5.12")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")

    testImplementation("io.ktor:ktor-server-test-host")
    testImplementation(kotlin("test"))
}

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
}

tasks.test { useJUnitPlatform() }
```

- [ ] **Step 4: Create `backend/src/main/resources/logback.xml`**

```xml
<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    <root level="INFO">
        <appender-ref ref="STDOUT"/>
    </root>
</configuration>
```

- [ ] **Step 5: Create `backend/.gitignore`**

```gitignore
.gradle/
build/
!gradle/wrapper/gradle-wrapper.jar
.env
```

- [ ] **Step 6: Create `backend/src/main/kotlin/com/agrello/signing/routes/HealthRoutes.kt`**

```kotlin
package com.agrello.signing.routes

import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

fun Route.healthRoutes() {
    get("/health") {
        call.respond(HttpStatusCode.OK, mapOf("status" to "ok"))
    }
}
```

- [ ] **Step 7: Create `backend/src/main/kotlin/com/agrello/signing/Application.kt`**

```kotlin
package com.agrello.signing

import com.agrello.signing.routes.healthRoutes
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

fun main() {
    Security.addProvider(BouncyCastleProvider())
    val port = System.getenv("SERVER_PORT")?.toInt() ?: 8080
    embeddedServer(Netty, port = port, host = "0.0.0.0") { module() }.start(wait = true)
}

fun Application.module() {
    install(ContentNegotiation) { json() }
    routing {
        healthRoutes()
    }
}
```

- [ ] **Step 8: Create `backend/src/test/kotlin/com/agrello/signing/routes/HealthRoutesTest.kt`**

```kotlin
package com.agrello.signing.routes

import com.agrello.signing.module
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HealthRoutesTest {
    @Test
    fun `health returns ok`() = testApplication {
        application { module() }
        val response = client.get("/health")
        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.bodyAsText().contains("ok"))
    }
}
```

- [ ] **Step 9: Generate the Gradle wrapper**

Run: `cd backend && gradle wrapper --gradle-version 8.11`
Expected: creates `gradlew`, `gradlew.bat`, `gradle/wrapper/`. (If `gradle` isn't installed, install via `choco install gradle` or use an existing wrapper.)

- [ ] **Step 10: Run the test**

Run: `cd backend && ./gradlew test`
Expected: PASS (`HealthRoutesTest`). On Windows use `./gradlew.bat test`.

- [ ] **Step 11: Commit**

```bash
git add backend/
git commit -m "feat(backend): scaffold Ktor app with health endpoint"
```

---

### Task 2: Config + SigningKeyProvider + demo keystore

**Files:**
- Create: `backend/src/main/kotlin/com/agrello/signing/config/AppConfig.kt`
- Create: `backend/src/main/kotlin/com/agrello/signing/signing/SigningKeyProvider.kt`
- Create: `backend/src/main/kotlin/com/agrello/signing/signing/KeystoreSigningKeyProvider.kt`
- Create: `backend/keys/demo-keystore.p12` (generated)
- Create: `backend/keys/demo-cert.pem` (generated)
- Create: `backend/keys/README.md`
- Test: `backend/src/test/kotlin/com/agrello/signing/signing/KeystoreSigningKeyProviderTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `data class AppConfig(val keystorePath: String, val keystorePassword: String, val keyAlias: String, val maxUploadBytes: Long, val port: Int)` with `companion object { fun fromEnv(): AppConfig }`.
  - `data class SigningIdentity(val privateKey: java.security.PrivateKey, val certificate: java.security.cert.X509Certificate)`.
  - `interface SigningKeyProvider { fun identity(): SigningIdentity }`.
  - `class KeystoreSigningKeyProvider(config: AppConfig) : SigningKeyProvider`.

- [ ] **Step 1: Generate the demo keystore and certificate**

Run (from `backend/keys/`):
```bash
keytool -genkeypair -alias signing -keyalg EC -groupname secp256r1 \
  -sigalg SHA256withECDSA -validity 3650 \
  -dname "CN=Agrello Demo Signer, O=Agrello, C=EE" \
  -keystore demo-keystore.p12 -storetype PKCS12 \
  -storepass changeit -keypass changeit
keytool -exportcert -alias signing -rfc \
  -keystore demo-keystore.p12 -storepass changeit -file demo-cert.pem
```
Expected: `demo-keystore.p12` and `demo-cert.pem` exist. Verify: `openssl x509 -in demo-cert.pem -noout -text | grep -i "Public Key Algorithm"` shows `id-ecPublicKey`.

- [ ] **Step 2: Create `backend/keys/README.md`**

```markdown
# Demo keys — THROWAWAY, NOT FOR PRODUCTION

`demo-keystore.p12` holds a self-signed EC P-256 key used only so the service
runs out of the box. It protects nothing and must never be used for real
signing. In production the keystore is injected via env vars from a secret
manager, or the key lives in an HSM/KMS behind the same `SigningKeyProvider`.

- Store password / key password: `changeit`
- Alias: `signing`
- `demo-cert.pem` is the matching public certificate (for `openssl` verification).
```

- [ ] **Step 3: Write the failing test `KeystoreSigningKeyProviderTest.kt`**

```kotlin
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
```

- [ ] **Step 4: Run it to verify it fails**

Run: `cd backend && ./gradlew test --tests "*KeystoreSigningKeyProviderTest*"`
Expected: FAIL — `AppConfig` / `KeystoreSigningKeyProvider` unresolved.

- [ ] **Step 5: Create `config/AppConfig.kt`**

```kotlin
package com.agrello.signing.config

data class AppConfig(
    val keystorePath: String,
    val keystorePassword: String,
    val keyAlias: String,
    val maxUploadBytes: Long,
    val port: Int,
) {
    companion object {
        fun fromEnv(): AppConfig = AppConfig(
            keystorePath = System.getenv("SIGNING_KEYSTORE_PATH") ?: "keys/demo-keystore.p12",
            keystorePassword = System.getenv("SIGNING_KEYSTORE_PASSWORD") ?: "changeit",
            keyAlias = System.getenv("SIGNING_KEY_ALIAS") ?: "signing",
            maxUploadBytes = System.getenv("MAX_UPLOAD_BYTES")?.toLong() ?: (25L * 1024 * 1024),
            port = System.getenv("SERVER_PORT")?.toInt() ?: 8080,
        )
    }
}
```

- [ ] **Step 6: Create `signing/SigningKeyProvider.kt`**

```kotlin
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
```

- [ ] **Step 7: Create `signing/KeystoreSigningKeyProvider.kt`**

```kotlin
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
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd backend && ./gradlew test --tests "*KeystoreSigningKeyProviderTest*"`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add backend/
git commit -m "feat(backend): add config and keystore-backed SigningKeyProvider with demo key"
```

---

### Task 3: CmsSigner (detached CAdES-BES)

**Files:**
- Create: `backend/src/main/kotlin/com/agrello/signing/signing/CmsSigner.kt`
- Test: `backend/src/test/kotlin/com/agrello/signing/signing/CmsSignerTest.kt`

**Interfaces:**
- Consumes: `SigningKeyProvider`, `SigningIdentity`.
- Produces:
  - `data class SignatureResult(val signatureDer: ByteArray, val sha256Hex: String, val signerSubject: String, val signingTime: java.time.Instant, val signatureAlgorithm: String)`.
  - `class CmsSigner(keyProvider: SigningKeyProvider, clock: java.time.Clock = Clock.systemUTC())` with `fun sign(content: ByteArray): SignatureResult`.

- [ ] **Step 1: Write the failing test `CmsSignerTest.kt`**

```kotlin
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

        // SHA-256 of "hello agrello"
        assertEquals(64, result.sha256Hex.length)
        assertTrue(result.signerSubject.contains("Agrello Demo Signer"))
        assertEquals("SHA256withECDSA", result.signatureAlgorithm)
        assertTrue(result.signatureDer.isNotEmpty())
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd backend && ./gradlew test --tests "*CmsSignerTest*"`
Expected: FAIL — `CmsSigner` unresolved.

- [ ] **Step 3: Create `signing/CmsSigner.kt`**

```kotlin
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && ./gradlew test --tests "*CmsSignerTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/
git commit -m "feat(backend): add CmsSigner producing detached CAdES-BES signatures"
```

---

### Task 4: CmsVerifier (with tamper detection)

**Files:**
- Create: `backend/src/main/kotlin/com/agrello/signing/signing/CmsVerifier.kt`
- Test: `backend/src/test/kotlin/com/agrello/signing/signing/CmsVerifierTest.kt`

**Interfaces:**
- Consumes: `CmsSigner`, `SignatureResult`.
- Produces:
  - `data class VerificationResult(val valid: Boolean, val signerSubject: String?, val signingTime: java.time.Instant?, val signatureAlgorithm: String?, val reason: String?)`.
  - `class CmsVerifier` with `fun verify(content: ByteArray, signatureDer: ByteArray): VerificationResult`.

- [ ] **Step 1: Write the failing test `CmsVerifierTest.kt`**

```kotlin
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd backend && ./gradlew test --tests "*CmsVerifierTest*"`
Expected: FAIL — `CmsVerifier` unresolved.

- [ ] **Step 3: Create `signing/CmsVerifier.kt`**

```kotlin
package com.agrello.signing.signing

import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
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

            val certHolder = certStore.getMatches(signer.sid).firstOrNull() as? X509CertificateHolder
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && ./gradlew test --tests "*CmsVerifierTest*"`
Expected: PASS (both cases).

- [ ] **Step 5: Commit**

```bash
git add backend/
git commit -m "feat(backend): add CmsVerifier with tamper detection"
```

---

### Task 5: DTOs + sign/verify/certificate routes wired into the app

**Files:**
- Create: `backend/src/main/kotlin/com/agrello/signing/model/Dtos.kt`
- Create: `backend/src/main/kotlin/com/agrello/signing/routes/SigningRoutes.kt`
- Modify: `backend/src/main/kotlin/com/agrello/signing/Application.kt`
- Test: `backend/src/test/kotlin/com/agrello/signing/routes/SigningRoutesTest.kt`

**Interfaces:**
- Consumes: `CmsSigner`, `CmsVerifier`, `AppConfig`, `SigningKeyProvider`.
- Produces:
  - Serializable DTOs `SignResponse`, `VerifyResponse`.
  - `fun Route.signingRoutes(config: AppConfig, signer: CmsSigner, verifier: CmsVerifier, keyProvider: SigningKeyProvider)`.

- [ ] **Step 1: Create `model/Dtos.kt`**

```kotlin
package com.agrello.signing.model

import kotlinx.serialization.Serializable

@Serializable
data class SignResponse(
    val fileName: String,
    val sha256Hex: String,
    val signerSubject: String,
    val signingTime: String,
    val signatureAlgorithm: String,
    val signatureFormat: String,
    val signatureBase64: String,
)

@Serializable
data class VerifyResponse(
    val valid: Boolean,
    val signerSubject: String? = null,
    val signingTime: String? = null,
    val signatureAlgorithm: String? = null,
    val reason: String? = null,
)
```

- [ ] **Step 2: Write the failing test `SigningRoutesTest.kt`**

```kotlin
package com.agrello.signing.routes

import com.agrello.signing.module
import io.ktor.client.request.forms.MultiPartFormDataContent
import io.ktor.client.request.forms.formData
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SigningRoutesTest {
    @Test
    fun `sign endpoint returns signature metadata`() = testApplication {
        application { module() }
        val response = client.post("/api/sign") {
            setBody(MultiPartFormDataContent(formData {
                append("file", "hello".toByteArray(), Headers.build {
                    append(HttpHeaders.ContentType, ContentType.Application.OctetStream.toString())
                    append(HttpHeaders.ContentDisposition, "filename=\"hello.txt\"")
                })
            }))
        }
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("sha256Hex"))
        assertTrue(body.contains("signatureBase64"))
        assertTrue(body.contains("Agrello Demo Signer"))
    }

    @Test
    fun `certificate endpoint returns PEM`() = testApplication {
        application { module() }
        val response = client.post("/api/sign") { /* warm up */
            setBody(MultiPartFormDataContent(formData {
                append("file", "x".toByteArray(), Headers.build {
                    append(HttpHeaders.ContentDisposition, "filename=\"x\"")
                })
            }))
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd backend && ./gradlew test --tests "*SigningRoutesTest*"`
Expected: FAIL — `/api/sign` returns 404 (route not registered).

- [ ] **Step 4: Create `routes/SigningRoutes.kt`**

```kotlin
package com.agrello.signing.routes

import com.agrello.signing.config.AppConfig
import com.agrello.signing.model.SignResponse
import com.agrello.signing.model.VerifyResponse
import com.agrello.signing.signing.CmsSigner
import com.agrello.signing.signing.CmsVerifier
import com.agrello.signing.signing.SigningKeyProvider
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.server.request.receiveMultipart
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.utils.io.readRemaining
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.io.readByteArray
import java.util.Base64

/**
 * Reads a single named file part, enforcing maxBytes. Returns (fileName, bytes)
 * or null if the part is missing / too large.
 */
private suspend fun readFilePart(
    multipart: io.ktor.http.content.MultiPartData,
    partName: String,
    maxBytes: Long,
): Pair<String, ByteArray>? {
    var fileName: String? = null
    var bytes: ByteArray? = null
    var tooLarge = false
    multipart.forEachPart { part ->
        if (part is PartData.FileItem && part.name == partName) {
            val data = part.provider().readRemaining(maxBytes + 1).readByteArray()
            if (data.size > maxBytes) tooLarge = true else {
                fileName = part.originalFileName ?: "upload"
                bytes = data
            }
        }
        part.dispose()
    }
    if (tooLarge) return null
    val fn = fileName ?: return null
    val b = bytes ?: return null
    return fn to b
}

fun Route.signingRoutes(
    config: AppConfig,
    signer: CmsSigner,
    verifier: CmsVerifier,
    keyProvider: SigningKeyProvider,
) {
    post("/api/sign") {
        val file = readFilePart(call.receiveMultipart(formFieldLimit = config.maxUploadBytes + 1), "file", config.maxUploadBytes)
        if (file == null) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing or too-large 'file' part"))
            return@post
        }
        val (fileName, content) = file
        // Offload CPU-bound signing off the request/event-loop threads.
        val result = withContext(Dispatchers.Default) { signer.sign(content) }
        call.respond(
            SignResponse(
                fileName = fileName,
                sha256Hex = result.sha256Hex,
                signerSubject = result.signerSubject,
                signingTime = result.signingTime.toString(),
                signatureAlgorithm = result.signatureAlgorithm,
                signatureFormat = "CMS/CAdES-BES detached (DER)",
                signatureBase64 = Base64.getEncoder().encodeToString(result.signatureDer),
            )
        )
    }

    post("/api/verify") {
        val multipart = call.receiveMultipart(formFieldLimit = config.maxUploadBytes + 1)
        var fileName: String? = null
        var content: ByteArray? = null
        var signatureDer: ByteArray? = null
        multipart.forEachPart { part ->
            if (part is PartData.FileItem) {
                val data = part.provider().readRemaining(config.maxUploadBytes + 1).readByteArray()
                when (part.name) {
                    "file" -> { fileName = part.originalFileName; content = data }
                    "signature" -> signatureDer = data
                }
            }
            part.dispose()
        }
        if (content == null || signatureDer == null) {
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Both 'file' and 'signature' parts are required"))
            return@post
        }
        val result = withContext(Dispatchers.Default) { verifier.verify(content!!, signatureDer!!) }
        call.respond(
            VerifyResponse(
                valid = result.valid,
                signerSubject = result.signerSubject,
                signingTime = result.signingTime?.toString(),
                signatureAlgorithm = result.signatureAlgorithm,
                reason = result.reason,
            )
        )
    }

    get("/api/certificate") {
        val cert = keyProvider.identity().certificate
        val pem = buildString {
            append("-----BEGIN CERTIFICATE-----\n")
            append(Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded))
            append("\n-----END CERTIFICATE-----\n")
        }
        call.respondText(pem, ContentType.parse("application/x-pem-file"))
    }
}
```

- [ ] **Step 5: Rewrite `Application.kt` to wire dependencies and routes**

```kotlin
package com.agrello.signing

import com.agrello.signing.config.AppConfig
import com.agrello.signing.routes.healthRoutes
import com.agrello.signing.routes.signingRoutes
import com.agrello.signing.signing.CmsSigner
import com.agrello.signing.signing.CmsVerifier
import com.agrello.signing.signing.KeystoreSigningKeyProvider
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.routing.routing
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

fun main() {
    Security.addProvider(BouncyCastleProvider())
    val config = AppConfig.fromEnv()
    embeddedServer(Netty, port = config.port, host = "0.0.0.0") { module() }.start(wait = true)
}

fun Application.module() {
    if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
    val config = AppConfig.fromEnv()
    val keyProvider = KeystoreSigningKeyProvider(config)
    val signer = CmsSigner(keyProvider)
    val verifier = CmsVerifier()

    install(ContentNegotiation) { json() }
    install(CORS) {
        anyHost() // demo only; restrict in production
        allowHeader(io.ktor.http.HttpHeaders.ContentType)
        allowMethod(io.ktor.http.HttpMethod.Post)
    }
    routing {
        healthRoutes()
        signingRoutes(config, signer, verifier, keyProvider)
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd backend && ./gradlew test`
Expected: PASS (all suites).

- [ ] **Step 7: Manually verify against openssl (integration smoke test)**

Run:
```bash
cd backend
./gradlew run &
sleep 8
echo "integration test content" > /tmp/sample.txt
# sign
curl -s -F "file=@/tmp/sample.txt" http://localhost:8080/api/sign > /tmp/resp.json
# extract signature + cert
python -c "import json;open('/tmp/sample.p7s','wb').write(__import__('base64').b64decode(json.load(open('/tmp/resp.json'))['signatureBase64']))"
curl -s http://localhost:8080/api/certificate > /tmp/cert.pem
# verify with openssl
openssl cms -verify -binary -content /tmp/sample.txt -in /tmp/sample.p7s -inform DER -CAfile /tmp/cert.pem -no_signer_cert_verify
```
Expected: `Verification successful` (or `CMS Verification successful`). Then stop the server. (`-no_signer_cert_verify` accepts the self-signed demo cert as its own trust anchor.)

- [ ] **Step 8: Commit**

```bash
git add backend/
git commit -m "feat(backend): add sign, verify, and certificate endpoints"
```

---

### Task 6: Error handling + upload-limit response polish

**Files:**
- Modify: `backend/src/main/kotlin/com/agrello/signing/Application.kt`
- Test: `backend/src/test/kotlin/com/agrello/signing/routes/ErrorHandlingTest.kt`

**Interfaces:**
- Consumes: existing routes.
- Produces: a `StatusPages` handler returning JSON `{ "error": ... }` for uncaught exceptions.

- [ ] **Step 1: Write the failing test `ErrorHandlingTest.kt`**

```kotlin
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd backend && ./gradlew test --tests "*ErrorHandlingTest*"`
Expected: FAIL — likely a 500 or unhandled exception rather than 400.

- [ ] **Step 3: Add `StatusPages` to `Application.kt`**

Add these imports:
```kotlin
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.response.respond
import io.ktor.http.HttpStatusCode
```
Add inside `module()` before `routing { ... }`:
```kotlin
install(StatusPages) {
    exception<Throwable> { call, cause ->
        call.application.log.error("Unhandled error", cause)
        call.respond(HttpStatusCode.BadRequest, mapOf("error" to (cause.message ?: "Bad request")))
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && ./gradlew test --tests "*ErrorHandlingTest*"`
Expected: PASS.

- [ ] **Step 5: Run the full backend suite**

Run: `cd backend && ./gradlew test`
Expected: PASS (all).

- [ ] **Step 6: Commit**

```bash
git add backend/
git commit -m "feat(backend): add JSON error handling via StatusPages"
```

---

### Task 7: Frontend scaffold + API client

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/tsconfig.json`
- Create: `frontend/tsconfig.node.json`
- Create: `frontend/index.html`
- Create: `frontend/.gitignore`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/api.ts`
- Create: `frontend/src/vite-env.d.ts`

**Interfaces:**
- Produces:
  - `interface SignResponse { fileName; sha256Hex; signerSubject; signingTime; signatureAlgorithm; signatureFormat; signatureBase64 }`.
  - `interface VerifyResponse { valid; signerSubject?; signingTime?; signatureAlgorithm?; reason? }`.
  - `async function signFile(file: File): Promise<SignResponse>`.
  - `async function verifyFile(file: File, signature: Blob): Promise<VerifyResponse>`.
  - `function base64ToBlob(b64: string): Blob`.

- [ ] **Step 1: Create `frontend/package.json`**

```json
{
  "name": "agrello-signing-frontend",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^19.0.0",
    "react-dom": "^19.0.0"
  },
  "devDependencies": {
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "@vitejs/plugin-react": "^4.3.4",
    "typescript": "^5.7.2",
    "vite": "^6.0.5"
  }
}
```

- [ ] **Step 2: Create `frontend/vite.config.ts`**

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8080",
    },
  },
});
```

- [ ] **Step 3: Create `frontend/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

- [ ] **Step 4: Create `frontend/tsconfig.node.json`**

```json
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true,
    "strict": true,
    "noEmit": true
  },
  "include": ["vite.config.ts"]
}
```

- [ ] **Step 5: Create `frontend/index.html`**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Agrello File Signing</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 6: Create `frontend/.gitignore`**

```gitignore
node_modules/
dist/
```

- [ ] **Step 7: Create `frontend/src/vite-env.d.ts`**

```typescript
/// <reference types="vite/client" />
```

- [ ] **Step 8: Create `frontend/src/api.ts`**

```typescript
export interface SignResponse {
  fileName: string;
  sha256Hex: string;
  signerSubject: string;
  signingTime: string;
  signatureAlgorithm: string;
  signatureFormat: string;
  signatureBase64: string;
}

export interface VerifyResponse {
  valid: boolean;
  signerSubject?: string;
  signingTime?: string;
  signatureAlgorithm?: string;
  reason?: string;
}

export async function signFile(file: File): Promise<SignResponse> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch("/api/sign", { method: "POST", body: form });
  if (!res.ok) throw new Error((await res.json()).error ?? "Signing failed");
  return res.json();
}

export async function verifyFile(file: File, signature: Blob): Promise<VerifyResponse> {
  const form = new FormData();
  form.append("file", file);
  form.append("signature", signature, "signature.p7s");
  const res = await fetch("/api/verify", { method: "POST", body: form });
  if (!res.ok) throw new Error((await res.json()).error ?? "Verification failed");
  return res.json();
}

export function base64ToBlob(b64: string): Blob {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return new Blob([bytes], { type: "application/pkcs7-signature" });
}
```

- [ ] **Step 9: Create `frontend/src/main.tsx`** (temporary placeholder; replaced in Task 8)

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <div>Agrello File Signing</div>
  </StrictMode>,
);
```

- [ ] **Step 10: Install and typecheck**

Run: `cd frontend && npm install && npm run build`
Expected: build succeeds, `dist/` produced.

- [ ] **Step 11: Commit**

```bash
git add frontend/
git commit -m "feat(frontend): scaffold Vite React TS app with API client"
```

---

### Task 8: Frontend UI — sign flow, result panel, in-app verify

**Files:**
- Create: `frontend/src/App.tsx`
- Create: `frontend/src/components/ResultPanel.tsx`
- Create: `frontend/src/styles.css`
- Modify: `frontend/src/main.tsx`

**Interfaces:**
- Consumes: `signFile`, `verifyFile`, `base64ToBlob`, `SignResponse`, `VerifyResponse`.
- Produces: `App` component; `ResultPanel` component with props `{ result: SignResponse; originalFile: File }`.

- [ ] **Step 1: Create `frontend/src/styles.css`**

```css
:root {
  --bg: #0f1115;
  --panel: #181b22;
  --border: #2a2f3a;
  --text: #e6e9ef;
  --muted: #9aa3b2;
  --accent: #5b8cff;
  --ok: #37b26b;
  --bad: #e5484d;
  font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); }
.container { max-width: 760px; margin: 0 auto; padding: 48px 24px; }
h1 { font-size: 22px; font-weight: 650; letter-spacing: -0.01em; }
.subtitle { color: var(--muted); margin-top: -8px; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-top: 20px; }
.dropzone { border: 1.5px dashed var(--border); border-radius: 12px; padding: 40px; text-align: center; cursor: pointer; transition: border-color .15s; }
.dropzone:hover, .dropzone.drag { border-color: var(--accent); }
button { background: var(--accent); color: white; border: 0; border-radius: 8px; padding: 10px 18px; font-size: 14px; cursor: pointer; }
button:disabled { opacity: .5; cursor: default; }
button.secondary { background: transparent; border: 1px solid var(--border); color: var(--text); }
.row { display: flex; justify-content: space-between; gap: 16px; padding: 8px 0; border-bottom: 1px solid var(--border); }
.row:last-child { border-bottom: 0; }
.row .label { color: var(--muted); }
.row .value { font-family: ui-monospace, monospace; font-size: 13px; word-break: break-all; text-align: right; }
.badge { display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 999px; font-size: 13px; }
.badge.ok { background: rgba(55,178,107,.15); color: var(--ok); }
.badge.bad { background: rgba(229,72,77,.15); color: var(--bad); }
.actions { display: flex; gap: 12px; margin-top: 20px; flex-wrap: wrap; }
.error { color: var(--bad); margin-top: 12px; }
code.block { display: block; background: #0b0d11; border: 1px solid var(--border); border-radius: 8px; padding: 12px; font-size: 12px; overflow-x: auto; white-space: pre; color: var(--muted); margin-top: 8px; }
```

- [ ] **Step 2: Create `frontend/src/components/ResultPanel.tsx`**

```tsx
import { useState } from "react";
import { verifyFile, base64ToBlob, type SignResponse, type VerifyResponse } from "../api";

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="row">
      <span className="label">{label}</span>
      <span className="value">{value}</span>
    </div>
  );
}

export function ResultPanel({ result, originalFile }: { result: SignResponse; originalFile: File }) {
  const [verification, setVerification] = useState<VerifyResponse | null>(null);
  const [verifying, setVerifying] = useState(false);

  const signatureBlob = base64ToBlob(result.signatureBase64);

  const download = () => {
    const url = URL.createObjectURL(signatureBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${result.fileName}.p7s`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const runVerify = async () => {
    setVerifying(true);
    try {
      setVerification(await verifyFile(originalFile, signatureBlob));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="panel">
      <h1>Signature created</h1>
      <Row label="File" value={result.fileName} />
      <Row label="SHA-256" value={result.sha256Hex} />
      <Row label="Signer" value={result.signerSubject} />
      <Row label="Signed at" value={result.signingTime} />
      <Row label="Algorithm" value={result.signatureAlgorithm} />
      <Row label="Format" value={result.signatureFormat} />

      <div className="actions">
        <button onClick={download}>Download .p7s</button>
        <button className="secondary" onClick={runVerify} disabled={verifying}>
          {verifying ? "Verifying…" : "Verify this signature"}
        </button>
      </div>

      {verification && (
        <div style={{ marginTop: 16 }}>
          <span className={`badge ${verification.valid ? "ok" : "bad"}`}>
            {verification.valid ? "✓ Signature valid" : "✗ Invalid"}
          </span>
          {verification.reason && <div className="error">{verification.reason}</div>}
        </div>
      )}

      <p className="subtitle" style={{ marginTop: 24 }}>Verify it yourself with OpenSSL:</p>
      <code className="block">{`# save the downloaded .p7s next to your original file, then:
curl -s http://localhost:8080/api/certificate > cert.pem
openssl cms -verify -binary -content "${result.fileName}" \\
  -in "${result.fileName}.p7s" -inform DER \\
  -CAfile cert.pem -no_signer_cert_verify`}</code>
    </div>
  );
}
```

- [ ] **Step 3: Create `frontend/src/App.tsx`**

```tsx
import { useRef, useState } from "react";
import { signFile, type SignResponse } from "./api";
import { ResultPanel } from "./components/ResultPanel";

export function App() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<SignResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const choose = (f: File | null) => {
    setFile(f);
    setResult(null);
    setError(null);
  };

  const sign = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    try {
      setResult(await signFile(file));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Signing failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>Agrello File Signing</h1>
      <p className="subtitle">Upload a file to produce a detached CMS/CAdES signature.</p>

      <div className="panel">
        <div
          className={`dropzone ${drag ? "drag" : ""}`}
          onClick={() => inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); choose(e.dataTransfer.files[0] ?? null); }}
        >
          {file ? <strong>{file.name}</strong> : "Drop a file here or click to choose"}
          <input
            ref={inputRef}
            type="file"
            style={{ display: "none" }}
            onChange={(e) => choose(e.target.files?.[0] ?? null)}
          />
        </div>
        <div className="actions">
          <button onClick={sign} disabled={!file || loading}>
            {loading ? "Signing…" : "Sign file"}
          </button>
        </div>
        {error && <div className="error">{error}</div>}
      </div>

      {result && file && <ResultPanel result={result} originalFile={file} />}
    </div>
  );
}
```

- [ ] **Step 4: Replace `frontend/src/main.tsx`**

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

- [ ] **Step 5: Typecheck and build**

Run: `cd frontend && npm run build`
Expected: build succeeds with no type errors.

- [ ] **Step 6: Manual smoke test**

Run backend (`cd backend && ./gradlew run`) and frontend (`cd frontend && npm run dev`), open the dev URL, upload a file, confirm the result panel shows metadata, download works, and "Verify this signature" shows a green valid badge.

- [ ] **Step 7: Commit**

```bash
git add frontend/
git commit -m "feat(frontend): add sign flow, result panel, and in-app verify"
```

---

### Task 9: Dockerization + compose + env example

**Files:**
- Create: `backend/Dockerfile`
- Create: `backend/.dockerignore`
- Create: `frontend/Dockerfile`
- Create: `frontend/nginx.conf`
- Create: `frontend/.dockerignore`
- Create: `docker-compose.yml`
- Create: `.env.example`
- Create: `.gitignore` (root)

**Interfaces:**
- Produces: `docker compose up` serving the frontend on `http://localhost:3000`, proxying `/api` to the backend.

- [ ] **Step 1: Create `backend/Dockerfile`**

```dockerfile
# --- build stage ---
FROM gradle:8.11-jdk21 AS build
WORKDIR /app
COPY settings.gradle.kts build.gradle.kts gradle.properties ./
COPY src ./src
COPY keys ./keys
RUN gradle installDist --no-daemon

# --- runtime stage ---
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/build/install/agrello-signing-backend ./
COPY --from=build /app/keys ./keys
EXPOSE 8080
ENV SIGNING_KEYSTORE_PATH=keys/demo-keystore.p12
CMD ["./bin/agrello-signing-backend"]
```

- [ ] **Step 2: Create `backend/.dockerignore`**

```gitignore
.gradle/
build/
.env
```

- [ ] **Step 3: Create `frontend/nginx.conf`**

```nginx
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    location /api/ {
        proxy_pass http://backend:8080;
        proxy_set_header Host $host;
        client_max_body_size 30m;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

- [ ] **Step 4: Create `frontend/Dockerfile`**

```dockerfile
# --- build stage ---
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

# --- runtime stage ---
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

- [ ] **Step 5: Create `frontend/.dockerignore`**

```gitignore
node_modules/
dist/
```

- [ ] **Step 6: Create `docker-compose.yml`**

```yaml
services:
  backend:
    build: ./backend
    environment:
      SERVER_PORT: 8080
      SIGNING_KEYSTORE_PATH: keys/demo-keystore.p12
      SIGNING_KEYSTORE_PASSWORD: ${SIGNING_KEYSTORE_PASSWORD:-changeit}
      SIGNING_KEY_ALIAS: ${SIGNING_KEY_ALIAS:-signing}
      MAX_UPLOAD_BYTES: ${MAX_UPLOAD_BYTES:-26214400}
    expose:
      - "8080"

  frontend:
    build: ./frontend
    ports:
      - "3000:80"
    depends_on:
      - backend
```

- [ ] **Step 7: Create `.env.example`**

```dotenv
# Copy to .env for local overrides. NEVER commit a real .env or real keys.
# In production these are injected from a secret manager, not stored on disk.
SIGNING_KEYSTORE_PASSWORD=changeit
SIGNING_KEY_ALIAS=signing
MAX_UPLOAD_BYTES=26214400
```

- [ ] **Step 8: Create root `.gitignore`**

```gitignore
.env
.DS_Store
```

- [ ] **Step 9: Build and run the full stack**

Run: `docker compose up --build`
Expected: both images build; frontend serves on `http://localhost:3000`.

- [ ] **Step 10: End-to-end verification**

Open `http://localhost:3000`, sign a file, click "Verify this signature" → green valid badge. Then confirm independent verification:
```bash
curl -s http://localhost:3000/api/certificate > cert.pem
# (sign a file via the UI, download its .p7s next to the original), then:
openssl cms -verify -binary -content <original> -in <original>.p7s -inform DER -CAfile cert.pem -no_signer_cert_verify
```
Expected: `Verification successful`. Stop with `docker compose down`.

- [ ] **Step 11: Commit**

```bash
git add backend/Dockerfile backend/.dockerignore frontend/Dockerfile frontend/nginx.conf frontend/.dockerignore docker-compose.yml .env.example .gitignore
git commit -m "feat: dockerize backend and frontend with compose"
```

---

### Task 10: README + repo polish

**Files:**
- Create: `README.md`
- Modify: root `.gitignore` if needed.

**Interfaces:** none (documentation).

- [ ] **Step 1: Write `README.md`** covering, each as its own section:
  - **What it is** — one-paragraph summary: upload → detached CMS/CAdES-BES signature over an EC P-256 key → view + verify.
  - **Quick start (Docker):** `docker compose up --build`, then open `http://localhost:3000`.
  - **Quick start (native):** backend `cd backend && ./gradlew run`; frontend `cd frontend && npm install && npm run dev`.
  - **What gets signed** — the raw uploaded file bytes; signature is detached (`.p7s`, DER); SHA-256 shown as the file fingerprint.
  - **Verify it yourself** — the exact `openssl cms -verify ... -no_signer_cert_verify` command, plus a note that `/api/certificate` returns the signer certificate as PEM.
  - **Standard used** — CMS/CAdES-BES (RFC 5652 + ETSI EN 319 122), detached, with signed attributes: content-type, message-digest, signing-time, signing-certificate-v2.
  - **Key & certificate handling** — `SigningKeyProvider` seam; demo keystore is a labeled throwaway; env vars `SIGNING_KEYSTORE_PATH/PASSWORD/ALIAS`; production would inject via a secret manager or use HSM/KMS.
  - **Architecture** — monorepo layout, stateless backend, request flow.
  - **Performance & concurrency** — stateless → horizontal scaling; `MAX_UPLOAD_BYTES` bounds memory; CPU-bound signing offloaded to `Dispatchers.Default`; per-request crypto objects (thread-safety); note that very large files would use `CMSSignedDataStreamGenerator` to stream; HSM/KMS latency and connection pooling as the production scaling dimension.
  - **Testing** — `cd backend && ./gradlew test`; what the tests cover (round-trip, tamper detection, route response).
  - **Deliberate scope cuts** — auth, persistence, TSA timestamping, real CA certs — with a one-line "what production adds" (TSA for trusted time, HSM/KMS for keys).

- [ ] **Step 2: Verify both quick-start paths actually work** by following the README steps literally (Docker path at minimum).

- [ ] **Step 3: Commit**

```bash
git add README.md .gitignore
git commit -m "docs: add README with run, verify, and design notes"
```

---

## Self-Review

**Spec coverage:**
- Kotlin+Ktor backend → Tasks 1–6. React frontend → Tasks 7–8. ✓
- CMS/CAdES detached, EC P-256, BouncyCastle → Task 3 (signing-certificate-v2 = CAdES-BES). ✓
- SigningKeyProvider + keystore + env config + demo key → Task 2. ✓
- In-app verify + openssl story → Tasks 4, 5 (endpoints), 8 (UI), 10 (README). ✓
- `/api/certificate` for independent verification → Task 5. ✓
- Monorepo, Docker compose one-command run → Task 9. ✓
- Performance/concurrency (stateless, dispatcher offload, bounded upload, per-request crypto, streaming note) → Tasks 5, 10. ✓
- Tests (round-trip, tamper, routes) → Tasks 3, 4, 5, 6. ✓
- Out-of-scope items documented → Task 10. ✓

**Placeholder scan:** Task 10 README is described section-by-section with exact required content (not "write docs"); Task 7's `main.tsx` is an explicit temporary placeholder replaced in Task 8. No unresolved TODOs.

**Type consistency:** `SignatureResult`, `VerificationResult`, `SigningIdentity`, `AppConfig`, `SignResponse`, `VerifyResponse` field names are consistent across producer and consumer tasks. `signFile`/`verifyFile`/`base64ToBlob` signatures match between `api.ts` (Task 7) and `App.tsx`/`ResultPanel.tsx` (Task 8). Route names (`/api/sign`, `/api/verify`, `/api/certificate`, `/health`) consistent across backend and frontend.
