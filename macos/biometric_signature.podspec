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

  # If your plugin requires a privacy manifest, for example if it collects user
  # data, update the PrivacyInfo.xcprivacy file to describe your plugin's
  # privacy impact, and then uncomment this line. For more information,
  # see https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
  s.resource_bundles = {'biometric_signature_privacy' => ['../ios/biometric_signature/Sources/biometric_signature/PrivacyInfo.xcprivacy']}

  s.dependency 'FlutterMacOS'

  s.platform = :osx, '10.15'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
