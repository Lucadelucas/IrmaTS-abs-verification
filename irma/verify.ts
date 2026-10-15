import * as gabiProofList from "../gabi/prooflist"
import * as gabikeys from "../gabi/gabikeys/keys"
import * as gabiProofs from "../gabi/proofs.ts"
import { PublicKey } from "../gabi/gabikeys/keys"
import { Configuration } from "./irmaconfig.ts"
import { AttributeConDisCon } from "./requests.ts"
import {
    decodeAttribute,
    decodeRandomBlind,
    MetadataAttribute,
    metadataFromInt,
} from "./attributes.ts"
import {
    AttributeTypeIdentifier,
    CredentialIdentifier,
    CredentialTypeIdentifier,
    Identifier,
    SchemeManagerIdentifier,
} from "./identifiers.ts"
import { CredentialType, TranslatedString } from "./descriptions.ts"
import { DisclosedAttributeIndex, DisclosedAttributeIndices } from "./messages.ts"
import { Timestamp } from "./timestamp.ts"
import { Encoding } from "../gabi/internal/common/hashtool.ts"
import * as signature from "./irma_signature"
import * as messages from "./messages"

/** status string for a single disclosed attribute (present, extra, null) */
export type AttributeProofStatus = string

/** overall status string for a verified proof (valid, invalid, expired, ...) */
export type ProofStatus = string

/** the possible outcomes of verifying a whole proof */
export const PROOF_STATUS_VALID: ProofStatus = "VALID"
export const PROOF_STATUS_INVALID: ProofStatus = "INVALID"
export const PROOF_STATUS_INVALID_TIMESTAMP: ProofStatus = "INVALID_TIMESTAMP"
export const PROOF_STATUS_UNMATCHED_REQUEST: ProofStatus = "UNMATCHED_REQUEST"
export const PROOF_STATUS_MISSING_ATTRIBUTES: ProofStatus = "MISSING_ATTRIBUTES"
export const PROOF_STATUS_EXPIRED: ProofStatus = "EXPIRED"

/** the possible outcomes for a single disclosed attribute */
export const ATTRIBUTE_PROOF_STATUS_PRESENT: AttributeProofStatus = "PRESENT"
export const ATTRIBUTE_PROOF_STATUS_EXTRA: AttributeProofStatus = "EXTRA"
export const ATTRIBUTE_PROOF_STATUS_NULL: AttributeProofStatus = "NULL"

/** a disclosed attribute with value, metadata, and verification status */
export type DisclosedAttribute = {
    rawValue?: string
    value: TranslatedString
    identifier: AttributeTypeIdentifier
    status: AttributeProofStatus
    issuanceTime: Date
    notRevoked: boolean
    notRevokedBefore?: Date
}

/**
 * pull one disclosed attribute out of a proof list at the given index and tag its revocation status
 * @param pl - the proof list to read from
 * @param index - which credential and which attribute within it
 * @param notrevoked - time bound to store as notRevokedBefore
 * @param conf - configuration used to resolve credential types
 * @returns [the disclosed attribute, its raw string value]
 */
export function extractAttribute(
    pl: gabiProofList.ProofList,
    index: DisclosedAttributeIndex,
    notrevoked: Date,
    conf: Configuration
): [DisclosedAttribute, string] {
    // reject if the requested credential is outside the proof list
    if (pl.proofList.length <= index.credentialIndex) {
        throw new Error("Credential index out of range")
    }

    // every entry is assumed to be a ProofD so we can index aDisclosed directly
    const proof = pl.proofList[index.credentialIndex]
    if (proof === undefined) {
        throw new Error(`Cannot access proof at index ${index.credentialIndex}`)
    }

    // metadata attr (index 1) gives the credential type; then parse the requested attribute
    const metadata: MetadataAttribute = metadataFromInt(proof.aDisclosed[1]!, conf)
    const [attr, str]: [DisclosedAttribute, string] = parseAttribute(
        index.attributeIndex,
        metadata,
        proof.aDisclosed[index.attributeIndex]!
    )

    // record the not-revoked-before bound and whether a nonrevocation proof was included
    attr.notRevokedBefore = notrevoked
    attr.notRevoked = proof.nonRevocationProof !== undefined

    return [attr, str]
}

/**
 * turn a raw attribute bigint into a DisclosedAttribute, decoding its value
 * @param index - position of the attribute in aDisclosed (1 is the metadata attribute)
 * @param metadata - metadata attribute that tells us the credential type and version
 * @param attr - the raw attribute value to decode
 * @returns [the disclosed attribute, its decoded string value]
 */
export function parseAttribute(
    index: number,
    metadata: MetadataAttribute,
    attr: bigint
): [DisclosedAttribute, string] {
    let attrID: AttributeTypeIdentifier
    let attrVal: string | undefined
    const credType: CredentialType | undefined = metadata.credentialType()

    // the credential type must be resolvable from the configuration
    if (credType === undefined) {
        throw new Error("ProofList contained a disclosure proof of an unknown credential type")
    }

    if (index === 1) {
        // index 1 is the metadata attribute itself: report the credential id with value "present"
        attrID = credType.identifier()
        attrVal = "present"
    } else {
        // regular attributes start at index 2; decode as random-blind or normal (version-dependent)
        attrID = credType.attributeTypes![index - 2]!.identifier()
        if (credType.attributeTypes![index - 2]!.randomBlind) {
            attrVal = decodeRandomBlind(attr)
        } else {
            attrVal = decodeAttribute(attr, metadata.version())
        }
    }

    // an undefined decoded value means the attribute is disclosed but null
    let status = ATTRIBUTE_PROOF_STATUS_PRESENT
    if (attrVal === undefined) {
        status = ATTRIBUTE_PROOF_STATUS_NULL
        attrVal = ""
    }

    return [
        {
            identifier: attrID,
            rawValue: attrVal,
            value: { "": attrVal, en: attrVal, nl: attrVal },
            status: status,
            notRevoked: false,
            issuanceTime: metadata.signingDate(),
        },
        attrVal,
    ]
}

/** a proof list extended with the attribute-level verification helpers we need here */
export class ProofList extends gabiProofList.ProofList {
    /**
     * @param proofList - the disclosure proofs this list wraps
     */
    constructor(proofList: gabiProofs.ProofD[]) {
        super(proofList)
    }

    /**
     * true if any credential in the list has expired
     * @param configuration - used to resolve credential types from metadata
     * @param tNow - reference time to compare against (defaults to now)
     * @param skipExpiryCheck - credential types that are exempt from the check
     * @returns whether at least one credential is expired
     */
    public expired(
        configuration: Configuration,
        tNow: Date,
        skipExpiryCheck: CredentialTypeIdentifier[]
    ): boolean {
        for (const proof of this.proofList) {
            // index 1 is the metadata attribute; derive the credential type and keys
            const metadata: MetadataAttribute = metadataFromInt(proof.aDisclosed[1]!, configuration)

            // some credential types are exempt from the expiry check
            let skipCheck: boolean = false
            if (metadata?.credentialType().identifier() !== undefined) {
                skipCheck = skipExpiryCheck.includes(metadata!.credentialType().identifier()!)
            }

            if (!skipCheck && tNow > metadata.expiry()) {
                return true
            }

            const pk: PublicKey = metadata.publicKey()
            if (Math.floor(metadata.signingDate().getTime() / 1000) > pk.expiryDate) {
                return true
            }
        }
        return false
    }

    /**
     * resolve the issuer public key for each proof from its metadata attribute
     * @param configuration - configuration the keys are looked up in
     * @returns one public key per proof, in the same order as the proof list
     */
    private extractPublicKeys(configuration: Configuration): gabikeys.PublicKey[] {
        const publicKeys: gabikeys.PublicKey[] = new Array(this.proofList.length)

        for (let i = 0; i < this.proofList.length; i++) {
            const proof = this.proofList[i]!

            // index 1 is the metadata attribute, from which the issuer key is resolved
            if (proof.aDisclosed[1] === undefined) {
                throw new Error("Missing metadata attribute")
            }

            // resolve the issuer public key referenced by this proof's metadata
            const metadata: MetadataAttribute = metadataFromInt(proof.aDisclosed[1], configuration)
            const publicKey: gabikeys.PublicKey = metadata.publicKey()

            if (publicKey === undefined) {
                throw new Error("Cannot extract public key from metadata")
            }

            publicKeys[i] = publicKey
        }

        return publicKeys
    }

    /**
     * cryptographically verify all proofs and check that singleton credentials occur at most once
     * @param configuration - configuration used to resolve keys and credential types
     * @param context - shared context value the proofs were made against
     * @param nonce - verifier nonce the proofs were made against
     * @param publickeys - verification keys (extracted from configuration if undefined)
     * @returns [whether everything verified, revocation times per proof]
     */
    public async verifyProofs(
        configuration: Configuration,
        context: bigint,
        nonce: bigint,
        publickeys: gabikeys.PublicKey[] | undefined,
    ): Promise<[boolean, Record<number, Date>]> {
        const proofList: gabiProofs.ProofD[] = this.proofList

        // empty proof lists are allowed; consistency with the request is checked elsewhere
        if (proofList.length === 0) {
            return [true, {}]
        }

        // extract public keys from the configuration when none are given
        if (publickeys === undefined) {
            publickeys = this.extractPublicKeys(configuration)
        }

        if (publickeys.length !== proofList.length) {
            throw new Error("Insufficient public keys to verify the proofs")
        }

        // per proof, the keyshare server name whose key is involved (empty means none)
        const keyshareServers: string[] = new Array(proofList.length).fill("")

        for (let i = 0; i < proofList.length; i++) {
            const schemeID: SchemeManagerIdentifier = Identifier.parent(publickeys[i]!.issuer)

            if (!configuration.schemeManagers[schemeID]?.distributed()) {
                keyshareServers[i] = "." // dummy value: no IRMA scheme will ever have this name
            } else {
                keyshareServers[i] = Identifier.name(schemeID)
            }
        }

        if (!(await this.verify(publickeys, context, nonce, keyshareServers))) {
            return [false, {}]
        }

        // check that any singleton credential occurs at most once in the proof list
        const singletons: Map<CredentialTypeIdentifier, boolean> = new Map()

        // per proof, the time up to which it is known to be not revoked
        const revocationTime: Record<number, Date> = {}

        for (let i = 0; i < proofList.length; i++) {
            if (!(proofList[i] instanceof gabiProofs.ProofD)) {
                continue
            }

            const proofD: gabiProofs.ProofD = proofList[i] as gabiProofs.ProofD
            const credentialType: CredentialType = metadataFromInt(
                proofD.aDisclosed[1]!,
                configuration
            ).credentialType()

            if (credentialType === undefined) {
                throw new Error("Received unknown credential type")
            }

            const id: CredentialTypeIdentifier = credentialType.identifier()

            if (credentialType.isSingleton) {
                if (!singletons.get(id)) {
                    singletons.set(id, true)
                } else {
                    return [false, {}]
                }
            }
        }

        return [true, revocationTime]
    }
}

/** a disclosure (proof list plus the indices of the attributes it discloses) we can verify */
export class Disclosure extends messages.Disclosure {
    /**
     * @param proofs - the proof list being disclosed
     * @param indices - which attributes in the list are disclosed
     */
    constructor(proofs: ProofList, indices: DisclosedAttributeIndices) {
        super(proofs, indices)
    }

    /**
     * verify the proofs, then check the disclosed attributes against the request and their expiry
     * @param configuration - configuration used for keys and credential types
     * @param context - shared context value the proofs were made against
     * @param nonce - verifier nonce the proofs were made against
     * @param publickeys - verification keys (extracted from configuration if undefined)
     * @param validAt - time the credentials must be valid at
     * @returns [disclosed attributes or undefined, proof status]
     */
    public async verifyAgainstRequest(
        configuration: Configuration,
        context: bigint,
        nonce: bigint,
        publickeys: gabikeys.PublicKey[] | undefined,
        validAt: Date
    ): Promise<[DisclosedAttribute[][] | undefined, ProofStatus]> {
        const proofs = this.proofs as ProofList
        const [valid, revtimes]: [boolean, Record<number, Date>] = await proofs!.verifyProofs(
            configuration,
            context,
            nonce,
            publickeys
        )

        if (!valid) {
            return [undefined, PROOF_STATUS_INVALID]
        }

        // extract the disclosed attributes and match them to the request, if present
        const required: AttributeConDisCon = new AttributeConDisCon()
        const skipExpiryCheck: CredentialTypeIdentifier[] = []
        const [complete, list] = this.disclosedAttributes(configuration, required, revtimes)

        // missing attributes when a requested disjunction is not satisfied
        if (!complete) {
            return [list, PROOF_STATUS_MISSING_ATTRIBUTES]
        }

        // check that all credentials are unexpired
        const proofList = this.proofs as ProofList
        if (proofList.expired(configuration, validAt, skipExpiryCheck)) {
            return [list, PROOF_STATUS_EXPIRED]
        }

        return [list, PROOF_STATUS_VALID]
    }
}

/** an attribute-based signature bundling the disclosure proof, message, and metadata */
export class SignedMessage extends signature.SignedMessage {
    /**
     * @param fields - the signature parts (context, nonce, message, timestamp, indices, ...)
     */
    constructor({
        ldContext,
        signature,
        indices,
        nonce,
        context,
        message,
        timestamp,
    }: Partial<SignedMessage>) {
        super({
            ldContext,
            signature,
            indices,
            nonce,
            context,
            message,
            timestamp,
        })
    }

    /**
     * verify the signature and that its disclosed attributes satisfy any requirements
     * @param configuration - configuration used for keys and credential types
     * @returns [disclosed attributes or undefined, proof status]
     */
    public async verify(
        configuration: Configuration
    ): Promise<[DisclosedAttribute[][] | undefined, ProofStatus]> {
        // a signature with no proofs can never be valid
        if (this.signature.proofList.length === 0) {
            return [undefined, PROOF_STATUS_INVALID]
        }

        // credentials must have been valid when the signature was created, so the
        // attached timestamp is the reference time (now when there is none)
        const time: Date = this.timestamp ? this.timestamp.time : new Date()

        // verify the disclosure proofs and that they satisfy the request, if present
        return await this.disclosure().verifyAgainstRequest(
            configuration,
            this.context,
            this.nonce,
            undefined,
            time
        )
    }
}

/** JSON shape of the signed Atum timestamp attached to a signature */
export type TimestampJSON = {
    Time: number
    ServerUrl: string
    Sig: { Alg: string; Data: string; PublicKey: string }
    Hashing?: { hash: string; prefix: string }
}

/** JSON shape of a disclosure index, naming a disclosed attribute by position */
export type IndexJSON = {
    cred: number
    attr: number
}

/** JSON shape of the inner signature object of an attribute-based signature */
export type SignatureJSON = {
    "@context"?: string
    signature: gabiProofs.ProofDJSON[]
    indices?: IndexJSON[][]
    nonce: string
    context: string
    message: string
    timestamp: TimestampJSON
}

/**
 * JSON shape of a full server session result (the response of an irma server
 * `GET /session/{token}/result`). Only the nested signature is used during
 * verification; the server's own token/status/proofStatus/disclosed are carried
 * along but not trusted, since verify() establishes validity independently.
 */
export type SessionResultJSON = {
    token?: string
    status?: string
    type?: string
    proofStatus?: string
    disclosed?: unknown
    signature: SignatureJSON
    [key: string]: unknown
}

/**
 * require a non-empty string, throwing a descriptive error otherwise
 * @param value the value to check
 * @param name the field name to report when it is missing
 * @returns the value, narrowed to string
 */
function requireString(value: unknown, name: string): string {
    if (typeof value !== "string" || value.length === 0) {
        throw new Error(`Invalid signature: missing or empty "${name}"`)
    }
    return value
}

/**
 * parse and validate the timestamp block, failing closed if any part is
 * missing. the timestamp signature is folded into the nonce, so an incomplete
 * timestamp would make verification meaningless.
 * @param ts the timestamp JSON from the signature
 * @returns the decoded Timestamp
 */
function parseTimestamp(ts: TimestampJSON | undefined): Timestamp {
    if (ts === null || typeof ts !== "object") {
        throw new Error('Invalid signature: missing "timestamp"')
    }
    if (typeof ts.Time !== "number") {
        throw new Error('Invalid signature: timestamp is missing a numeric "Time"')
    }
    requireString(ts.ServerUrl, "timestamp.ServerUrl")
    if (ts.Sig === null || typeof ts.Sig !== "object") {
        throw new Error('Invalid signature: timestamp is missing "Sig"')
    }
    requireString(ts.Sig.Alg, "timestamp.Sig.Alg")
    requireString(ts.Sig.Data, "timestamp.Sig.Data")
    requireString(ts.Sig.PublicKey, "timestamp.Sig.PublicKey")

    return {
        time: new Date(ts.Time * 1000),
        serverURL: ts.ServerUrl,
        sig: {
            alg: ts.Sig.Alg,
            data: Encoding.base64ToBytes(ts.Sig.Data),
            publicKey: Encoding.base64ToBytes(ts.Sig.PublicKey),
        },
    }
}

/**
 * map the disclosure indices from their JSON form, naming each attribute by its
 * credential and attribute position. returns undefined when no indices are
 * present so the SignedMessage falls back to its default.
 * @param indices the indices array from the signature JSON, if any
 * @returns the mapped indices, or undefined when none were provided
 */
function parseIndices(indices?: IndexJSON[][]): DisclosedAttributeIndices | undefined {
    if (indices === undefined) {
        return undefined
    }
    if (!Array.isArray(indices)) {
        throw new Error('Invalid signature: "indices" must be an array')
    }
    return indices.map((conjunction) => {
        if (!Array.isArray(conjunction)) {
            throw new Error('Invalid signature: each "indices" entry must be an array')
        }
        return conjunction.map((index) => {
            if (typeof index?.cred !== "number" || typeof index?.attr !== "number") {
                throw new Error('Invalid signature: each index needs numeric "cred" and "attr"')
            }
            return {
                credentialIndex: index.cred,
                attributeIndex: index.attr,
                identifier: new CredentialIdentifier({}),
            }
        })
    })
}

/**
 * parse the inner signature object of an attribute-based signature into a
 * verifiable SignedMessage, failing closed when an essential field is missing.
 * every proof is validated, the timestamp is required, and the nonce is derived
 * so the result can be passed straight to verify(). both v1 (empty @context)
 * and v2 signatures are accepted.
 * @param input the inner signature, either as a JSON string or a parsed object
 * @returns the parsed SignedMessage with its nonce already set
 */
export async function parseSignedMessage(input: string | SignatureJSON): Promise<SignedMessage> {
    const parsed: SignatureJSON = typeof input === "string" ? JSON.parse(input) : input

    // at least one proof, each validated and decoded by ProofD.fromJSON
    if (!Array.isArray(parsed.signature) || parsed.signature.length === 0) {
        throw new Error('Invalid signature: "signature" must be a non-empty array of proofs')
    }
    const proofList: ProofList = new ProofList([])
    for (const proof of parsed.signature) {
        proofList.proofList.push(gabiProofs.ProofD.fromJSON(proof))
    }

    // the timestamp is required and must be complete
    const timestamp: Timestamp = parseTimestamp(parsed.timestamp)

    // context must be present and decodable, but is not pinned to a fixed value
    const context: bigint = Encoding.base64ToBigInt(requireString(parsed.context, "context"))

    // message must be present, but may be the empty string
    if (typeof parsed.message !== "string") {
        throw new Error('Invalid signature: missing "message"')
    }

    // nonce must be present; setNonce derives the value actually signed
    requireString(parsed.nonce, "nonce")

    const message = new SignedMessage({
        ldContext: typeof parsed["@context"] === "string" ? parsed["@context"] : "",
        signature: proofList,
        indices: parseIndices(parsed.indices),
        context: context,
        message: parsed.message,
        timestamp: timestamp,
    })

    await message.setNonce(parsed.nonce)

    return message
}

/**
 * parse a full server session result into a verifiable SignedMessage by
 * extracting and parsing its inner signature. the server's own status and
 * proofStatus are ignored, since verify() establishes validity independently.
 * @param input the session result, either as a JSON string or a parsed object
 * @returns the parsed SignedMessage with its nonce already set
 */
export async function parseSessionResult(input: string | SessionResultJSON): Promise<SignedMessage> {
    const parsed: SessionResultJSON = typeof input === "string" ? JSON.parse(input) : input

    const signature: unknown = parsed?.signature
    if (signature === null || typeof signature !== "object" || Array.isArray(signature)) {
        throw new Error('Invalid session result: missing inner "signature" object')
    }

    return parseSignedMessage(signature as SignatureJSON)
}
