package com.visionflutter.biometric_signature

import android.util.Base64

object FormatUtils {
    data class FormattedOutput(
        val value: String,
        val format: KeyFormat,
        val pemLabel: String? = null
    )

    fun formatOutput(
        bytes: ByteArray,
        format: KeyFormat,
        label: String = "PUBLIC KEY"
    ): FormattedOutput =
        when (format) {
            KeyFormat.BASE64 -> FormattedOutput(
                Base64.encodeToString(bytes, Base64.NO_WRAP),
                format
            )
            KeyFormat.PEM -> FormattedOutput(
                "-----BEGIN $label-----\n${
                    Base64.encodeToString(bytes, Base64.NO_WRAP).chunked(64).joinToString("\n")
                }\n-----END $label-----",
                format,
                label
            )
            KeyFormat.HEX -> FormattedOutput(bytesToHex(bytes), format)
            KeyFormat.RAW -> FormattedOutput(Base64.encodeToString(bytes, Base64.NO_WRAP), format)
        }

    fun parsePayload(payload: String, format: PayloadFormat): ByteArray {
        return when (format) {
            PayloadFormat.BASE64, PayloadFormat.RAW -> decodeBase64(payload)
            PayloadFormat.HEX -> hexToBytes(payload)
        }
    }

    // The standard alphabet, with padding only at the end.
    private val base64Payload = Regex("[A-Za-z0-9+/]*={0,2}")

    /**
     * Decodes standard Base64, ignoring whitespace such as the line breaks of
     * wrapped Base64. android.util.Base64 skips every other character outside
     * its alphabet too, so "A!Q==" would decode as "AQ==": reject those instead.
     */
    private fun decodeBase64(payload: String): ByteArray {
        val compact = payload.filterNot { it == ' ' || it == '\t' || it == '\r' || it == '\n' }
        require(base64Payload.matches(compact)) { "Invalid Base64" }
        return Base64.decode(compact, Base64.NO_WRAP)
    }

    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun hexToBytes(hex: String): ByteArray {
        val cleanHex = if (hex.length % 2 != 0) "0$hex" else hex
        return cleanHex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
