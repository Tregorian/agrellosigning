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
