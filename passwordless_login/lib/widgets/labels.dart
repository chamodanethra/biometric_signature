import 'package:examples_shared/attestation.dart';

/// What a trust tier means, in one or two sentences.
String tierExplanation(TrustTier tier) => switch (tier) {
      TrustTier.strongBox => 'Generated in StrongBox, a separate secure '
          'element, as proven by a certificate chain up to Google’s root.',
      TrustTier.tee => 'Generated in the TEE (trusted execution '
          'environment), as proven by a certificate chain up to Google’s '
          'root.',
      TrustTier.untrusted => 'An attestation was sent but did not verify '
          '(e.g. an emulator’s software root). Accepted only because '
          '"Require attestation" is off; treat it like an unattested key.',
      TrustTier.none => 'No attestation: iOS, macOS and Windows cannot '
          'attest individual keys. The server has the public key but cannot '
          'tell where the private key lives.',
    };
