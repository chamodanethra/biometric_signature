# Keep the plugin class registered by Flutter
-keep class com.visionflutter.biometric_signature.BiometricSignaturePlugin { *; }

# Keep Pigeon-generated API interface, data classes, enums, and codec (needed for serialization)
-keep class com.visionflutter.biometric_signature.BiometricSignatureApi { *; }
-keep class com.visionflutter.biometric_signature.FlutterError { *; }
-keep enum com.visionflutter.biometric_signature.* { *; }
-keep class com.visionflutter.biometric_signature.*Result { *; }
-keep class com.visionflutter.biometric_signature.*Config { *; }
-keep class com.visionflutter.biometric_signature.BiometricAvailability { *; }
-keep class com.visionflutter.biometric_signature.KeyInfo { *; }

# Keep class names only (not members) for readable stack traces
-keepnames class com.visionflutter.biometric_signature.**

# Keep reflection targets in androidx.biometric for detecting biometric types
-keep class androidx.biometric.BiometricManager {
    *** getStrings(...);
}
-keep class androidx.biometric.BiometricManager$Strings {
    *** getButtonLabel(...);
    *** getPromptMessage(...);
    *** getSettingButtonLabel(...);
}
