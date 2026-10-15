/**
 * sha256 hash of a single file in a scheme, stored as raw bytes
 */
export type SchemeFileHash = Uint8Array

/**
 * maps each file path in a scheme to its expected hash, used to check the
 * scheme's contents haven't been tampered with
 */
export type SchemeManagerIndex = Record<string, SchemeFileHash>

/**
 * status string describing the state of a scheme manager (e.g. valid, invalid)
 */
export type SchemeManagerStatus = string

/**
 * an error tied to a specific scheme, bundling which scheme failed, its status,
 * and the underlying error
 */
export type SchemeManagerError = {
    Scheme: string
    Status: SchemeManagerStatus
    Err: Error
}
