// Version selection is part of the owner-approved deployment manifest.
// Amounts are a reproducible test configuration, not a calibrated market price.
import { BOUNTY_TEST_ECONOMICS } from '../../fhe-pod/scripts/bounty-economics.mjs';
export function nonlinearProfile(protocol = 'canonical') {
 if (protocol === 'canonical') return Object.freeze({protocol, kind: 'canonical-nonlinear',
  game: 'CanonicalFHEDisputeGame', availability: 'AuthenticatedTraceAvailability', extraConstructorArgs: []});
 if (protocol === 'bounty-v2') return Object.freeze({protocol, kind: 'canonical-bounty-nonlinear-v2',
  game: 'CanonicalBountyFHEDisputeGame', availability: 'BountyTraceAvailability',
  economics: BOUNTY_TEST_ECONOMICS,
  extraConstructorArgs: BOUNTY_TEST_ECONOMICS.extraConstructorArgs});
 throw Error('unsupported nonlinear protocol: ' + protocol);
}
export function nonlinearManifestProfile(kind) {
 for (const name of ['canonical', 'bounty-v2']) {
  const profile = nonlinearProfile(name);
  if (kind === profile.kind) return profile;
 }
 throw Error('unsupported nonlinear workflow manifest kind: ' + kind);
}
