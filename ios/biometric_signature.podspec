#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint biometric_signature.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'biometric_signature'
  s.version          = '11.1.0'
  s.summary          = 'Hardware-backed biometric signatures for Flutter.'
  s.description      = <<-DESC
Create cryptographic signatures using Secure Enclave, StrongBox, and Windows Hello.
                       DESC
  s.homepage         = 'https://github.com/chamodanethra/biometric_signature'
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = { 'Chamoda Nethra' => 'chamodananayakkara@gmail.com' }
  s.source           = { :git => 'https://github.com/chamodanethra/biometric_signature.git', :tag => s.version.to_s }
  s.source_files = 'biometric_signature/Sources/biometric_signature/**/*.swift'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # If your plugin requires a privacy manifest, for example if it uses any
  # required reason APIs, update the PrivacyInfo.xcprivacy file to describe your
  # plugin's privacy impact, and then uncomment this line. For more information,
  # see https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
  s.resource_bundles = {'flutter_plugin_privacy' => ['biometric_signature/Sources/biometric_signature/PrivacyInfo.xcprivacy']}
end
