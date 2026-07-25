package com.visionflutter.biometric_signature

import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

object Constants {
    const val KEYSTORE_PROVIDER = "AndroidKeyStore"

    private const val DEFAULT_BIOMETRIC_KEY_ALIAS = "biometric_key"
    private const val DEFAULT_MASTER_KEY_ALIAS = "biometric_master_key"
    private const val DEFAULT_EC_WRAPPED_FILENAME = "biometric_ec_wrapped.bin"
    private const val DEFAULT_EC_PUB_FILENAME = "biometric_ec_pub.der"

    fun biometricKeyAlias(userAlias: String?): String =
        if (userAlias == null) DEFAULT_BIOMETRIC_KEY_ALIAS
        else "biometric_key_$userAlias"

    fun masterKeyAlias(userAlias: String?): String =
        if (userAlias == null) DEFAULT_MASTER_KEY_ALIAS
        else "biometric_master_key_$userAlias"

    fun ecWrappedFilename(userAlias: String?): String =
        if (userAlias == null) DEFAULT_EC_WRAPPED_FILENAME
        else "biometric_ec_wrapped_$userAlias.bin"

    fun ecPubFilename(userAlias: String?): String =
        if (userAlias == null) DEFAULT_EC_PUB_FILENAME
        else "biometric_ec_pub_$userAlias.der"

    // Prefix used to identify plugin-managed keys in the KeyStore
    const val KEY_ALIAS_PREFIX = "biometric_key_"
    const val MASTER_KEY_ALIAS_PREFIX = "biometric_master_key_"

    const val EC_PUBKEY_SIZE = 65
    const val GCM_TAG_BITS = 128
    const val GCM_TAG_BYTES = 16
    const val AES_KEY_SIZE = 16
    const val GCM_IV_SIZE = 12

    // RSA decryption transformations, in the order decryptRsa tries them.
    // Transformation names that embed a digest ("OAEPWithSHA-256AndMGF1Padding") only pin the
    // main digest and leave MGF1 to the provider, so the primary path uses the bare
    // "OAEPPadding" name and supplies both digests via RSA_OAEP_SHA256_MGF1_SHA1.
    const val RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPPadding"
    const val RSA_OAEP_SHA256_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    const val RSA_PKCS1_TRANSFORMATION = "RSA/ECB/PKCS1Padding"

    /**
     * OAEP parameters for RSA decryption: SHA-256 as the main digest, SHA-1 as the MGF1 digest,
     * empty label.
     *
     * SHA-1 is deliberate. AndroidKeyStore has always applied SHA-1 for MGF1 when the
     * transformation name leaves it unspecified, so every ciphertext produced against a key from
     * an earlier plugin version was built with these exact parameters. Pinning them keeps that
     * ciphertext decryptable instead of tying it to an undocumented provider default.
     *
     * OAEPParameterSpec is immutable, so a single shared instance is safe to reuse.
     */
    val RSA_OAEP_SHA256_MGF1_SHA1: OAEPParameterSpec = OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA1,
        PSource.PSpecified.DEFAULT
    )
}
