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
