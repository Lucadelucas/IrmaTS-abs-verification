import { Configuration } from "./irmaconfig.ts"
import {
    parseSessionResult,
    PROOF_STATUS_INVALID,
    type DisclosedAttribute,
    type ProofStatus,
    type SessionResultJSON,
    type SignedMessage,
} from "./verify.ts"
import { Identifier, type CredentialTypeIdentifier, type IssuerIdentifier } from "./identifiers.ts"

/** the outcome of verifying a signature */
export type VerificationResult = {
    /** the disclosed attributes per conjunction, or undefined when invalid */
    attributes: DisclosedAttribute[][] | undefined
    /** the detailed proof status (VALID, INVALID, EXPIRED, ...) */
    status: ProofStatus
}

/**
 * verify a Yivi/IRMA attribute-based signature contained in a full server
 * session result, in a single call.
 *
 * the disclosed ids only decide what to download; correctness is still enforced
 * cryptographically, since the credential's metadata hash is bound into the
 * signature, so a mismatched credential simply fails verification.
 *
 * **WARNING** *Currently does not verify signature of fetched scheme nor atumd timestamp*
 * @param response the full irma session result json
 * @param configuration a preloaded configuration to reuse; when omitted, one is
 * downloaded based on the result's disclosed attribute ids
 * @returns disclosed attributes and proof status
 */
export async function verifySignature(
    response: string | SessionResultJSON,
    configuration?: Configuration
): Promise<VerificationResult> {
    const parsed: SessionResultJSON = typeof response === "string" ? JSON.parse(response) : response

    configuration = configuration ?? (await autoConfigure(parsed))

    const signed: SignedMessage = await parseSessionResult(parsed)

    // if any error isn't caught by the verification function itself,
    // like for parsing errors, have a final catch that invalidates the proof
    let result: [DisclosedAttribute[][] | undefined, ProofStatus]
    try {
        result = await signed.verify(configuration)
    } catch {
        return { attributes: undefined, status: PROOF_STATUS_INVALID }
    }

    const [attributes, status] = result
    return { attributes, status }
}

/**
 * build a Configuration for a session result by downloading the credential types
 * named in its disclosed attributes and the matching issuer public keys.
 * @param response the parsed session result
 * @returns a configuration ready to verify the result's signature
 */
async function autoConfigure(response: SessionResultJSON): Promise<Configuration> {
    const credentialTypeIDs = credentialTypeIdentifiers(response)
    if (credentialTypeIDs.length === 0) {
        throw new Error(
            "Cannot auto-configure: the session result has no disclosed attributes to determine which credential types to load"
        )
    }

    const configuration = new Configuration({})

    // download each credential type description (also registers its scheme/issuer)
    await Promise.all(
        credentialTypeIDs.map((credentialTypeID) =>
            configuration.fetchCredentialType(credentialTypeID)
        )
    )

    // download the public keys for every issuer involved
    const issuerIDs = new Set<IssuerIdentifier>(credentialTypeIDs.map((id) => Identifier.parent(id)))
    await Promise.all([...issuerIDs].map((issuerID) => configuration.fetchPublicKeys(issuerID)))

    // map credential type ids to their metadata hashes so attributes resolve
    await configuration.reverseReverseHashes()

    return configuration
}

/**
 * the unique credential type identifiers referenced by a result's disclosed attributes.
 * @param response the parsed session result
 * @returns the distinct credential type identifiers
 */
function credentialTypeIdentifiers(response: SessionResultJSON): CredentialTypeIdentifier[] {
    const ids = new Set<CredentialTypeIdentifier>()

    const disclosed: unknown = response.disclosed
    if (Array.isArray(disclosed)) {
        for (const conjunction of disclosed) {
            if (!Array.isArray(conjunction)) {
                continue
            }
            for (const attribute of conjunction) {
                const id: unknown = (attribute as { id?: unknown })?.id
                if (typeof id !== "string") {
                    continue
                }
                const parts = id.split(".")
                if (parts.length >= 3) {
                    ids.add(parts.slice(0, 3).join("."))
                }
            }
        }
    }

    return [...ids]
}
