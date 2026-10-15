export { verifySignature } from "./irma/api.ts"

// Result shape for verifySignature (type-only, no runtime cost).
export type { VerificationResult } from "./irma/api.ts"

// Result vocabulary: the proof-status values verify() can actually return,
// the attribute shape, and the input type.
export { PROOF_STATUS_VALID, PROOF_STATUS_INVALID, PROOF_STATUS_EXPIRED } from "./irma/verify.ts"
export type { ProofStatus, DisclosedAttribute, SessionResultJSON } from "./irma/verify.ts"
