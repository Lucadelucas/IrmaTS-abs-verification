
/**
 * a signed Atum timestamp attached to an attribute-based signature.
 * proves the signature existed at a certain point in time
 */
export type Timestamp = {
    time: Date
    serverURL: string
    sig: Signature
    hashing?: Hashing
}

/**
 * the cryptographic signature carried by a Timestamp,
 * bundled with the algorithm and the key needed to verify it
 */
type Signature = {
    alg: SignatureAlgorithm
    data: Uint8Array
    publicKey: Uint8Array
}

/**
 * name of a signature algorithm, e.g. the ed25519 scheme Atum uses
 */
type SignatureAlgorithm = string

/**
 * describes how a message was hashed down to a nonce before being signed
 */
type Hashing = {
    hash: Hash
    prefix: Uint8Array
}

/**
 * name of a hash function used when reducing a message to a nonce
 */
type Hash = string
