/**
 * non-revocation proof showing a credential's witness still validates against
 * the current accumulator, i.e. the credential hasn't been revoked.
 * cr, cu and nu are the commitments, and responses holds the schnorr-style
 * answers keyed by name.
 */
export type Proof = {
    cr: bigint                              // commitment cr = g^r2 * h^r3 = g^epsilon * h^zeta
    cu: bigint                              // commitment cu = u * h^r2
    nu: bigint                              // commitment nu = cu^e * h^(-e*r2) = cu^alpha * h^-beta
    challenge: bigint                       // fiat-shamir challenge tying the commitments together
    responses: Record<string, bigint>       // schnorr responses, keyed by the value they answer for
    // signedAccumulator: SignedAccumulator
    // acc: Accumulator                     // pulled out of signedAccumulator while verifying
}
