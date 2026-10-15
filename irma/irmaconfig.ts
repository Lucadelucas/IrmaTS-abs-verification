import * as gabikeys from "../gabi/gabikeys/keys"
import { BigIntTool } from "../gabi/internal/common/mathutil.ts"
import { PublicKey } from "../gabi/gabikeys/keys"
import { XMLParser } from "fast-xml-parser"
import {
    AttributeTypeIdentifier,
    CredentialTypeIdentifier,
    Identifier,
    IssuerIdentifier,
    IssueWizardIdentifier,
    RequestorIdentifier,
    RequestorSchemeIdentifier,
    SchemeManagerIdentifier,
} from "./identifiers.ts"
import {
    AttributeType,
    CredentialType,
    Issuer,
    IssueWizard,
    RequestorInfo,
    RequestorScheme,
    SchemeManager,
} from "./descriptions.ts"
import type { Scheduler } from "node:timers/promises"
import { PrivateKeyRing, PrivateKeyRingMerge } from "./keyring.ts"
import { RevocationSettings, RevocationStorage } from "./revocation.ts"
import { SchemeManagerError } from "./schemes.ts"
import { DEFAULT_SYSTEM_PARAMETERS, SystemParameters } from "../gabi/gabikeys/sysparams.ts"

// base url of the yivi scheme host we download issuer public keys from
const SCHEME_HOST_URL = "https://schemes.yivi.app"

/**
 * public part of a keyshare-server rsa key
 */
type rsaPublicKey = {
    N: bigint // modulus n
    E: number // public exponent e
}

/**
 * in-memory registry of everything loaded from an irma_configuration folder:
 * schemes, issuers, credential and attribute types, plus the issuer public keys
 * needed to verify proofs. acts as the central lookup table during verification.
 */
export class Configuration {
    schemeManagers: Record<SchemeManagerIdentifier, SchemeManager>
    issuers: Record<IssuerIdentifier, Issuer>
    credentialTypes: Record<CredentialTypeIdentifier, CredentialType>
    attributeTypes: Record<AttributeTypeIdentifier, AttributeType>
    kssPublicKeys: Record<SchemeManagerIdentifier, Record<number, rsaPublicKey>>
    publicKeys?: Record<IssuerIdentifier, Record<number, gabikeys.PublicKey>>
    reverseHashes: Record<string, CredentialTypeIdentifier>

    // loaded requestor scheme data
    requestorSchemes: Record<RequestorSchemeIdentifier, RequestorScheme>
    requestors: Record<string, RequestorInfo>

    issueWizards: Record<IssueWizardIdentifier, IssueWizard>

    // requestor schemes that failed to parse, keyed to the error that broke them
    disabledRequestorSchemes: Record<RequestorIdentifier, SchemeManagerError>

    // schemes that failed to parse, keyed to the error that broke them
    disabledSchemeManagers: Record<SchemeManagerIdentifier, SchemeManagerError>

    // listeners called whenever the configuration changes
    updateListeners?: ConfigurationListener[]

    // path to the irma_configuration folder this instance represents
    path: string
    privateKeys: PrivateKeyRing
    revocation?: RevocationStorage
    scheduler?: Scheduler
    warnings: string[]

    options: ConfigurationOptions
    initialized: boolean
    assets: string
    readOnly: boolean

    constructor({
        schemeManagers = {},
        issuers = {},
        credentialTypes = {},
        attributeTypes = {},
        kssPublicKeys = {},
        publicKeys = undefined,
        reverseHashes = {},
        requestorSchemes = {},
        requestors = {},
        issueWizards = {},
        disabledRequestorSchemes = {},
        disabledSchemeManagers = {},
        updateListeners = undefined,
        path = "",
        privateKeys = undefined,
        revocation = undefined,
        scheduler = undefined,
        warnings = [],
        options = new ConfigurationOptions(),
        initialized = false,
        assets = "",
        readOnly = false,
    }: Partial<Configuration>) {
        this.schemeManagers = schemeManagers
        this.issuers = issuers
        this.credentialTypes = credentialTypes
        this.attributeTypes = attributeTypes
        this.kssPublicKeys = kssPublicKeys
        this.publicKeys = publicKeys
        this.reverseHashes = reverseHashes
        this.requestorSchemes = requestorSchemes
        this.requestors = requestors
        this.issueWizards = issueWizards
        this.disabledRequestorSchemes = disabledRequestorSchemes
        this.disabledSchemeManagers = disabledSchemeManagers
        this.updateListeners = updateListeners
        this.path = path
        if (privateKeys === undefined) {
            this.privateKeys = new PrivateKeyRingMerge()
        } else {
            this.privateKeys = privateKeys
        }
        this.revocation = revocation
        this.scheduler = scheduler
        this.warnings = warnings
        this.options = options
        this.initialized = initialized
        this.assets = assets
        this.readOnly = readOnly
    }

    /**
     * look up a credential type by the 16-byte metadata hash stored in an attribute
     * the hash is base64 encoded and matched against the precomputed reverseHashes map,
     * so reverseReverseHashes must have run first or this throws
     * @param hash - first 16 bytes of sha-256 of the credential id
     * @returns the matching credential type
     */
    public hashToCredentialType(hash: Uint8Array): CredentialType {
        const strb64 = btoa(String.fromCharCode(...hash))

        const credentialTypeIdentifier = this.reverseHashes[strb64]
        if (!credentialTypeIdentifier) {
            throw new Error("Unable to find credentialTypeIdentifier")
        }

        const credentialType = this.credentialTypes[credentialTypeIdentifier]
        if (!credentialType) {
            throw new Error("Unable to find credentialType")
        }

        return credentialType
    }

    /**
     * fill the reverseHashes map for every loaded credential type
     * maps base64(first 16 bytes of sha-256(id)) -> credential type id, doing the
     * async hashing once up front so later lookups in hashToCredentialType stay sync
     * @returns resolves once every credential type has been hashed
     */
    public async reverseReverseHashes(): Promise<void> {
        const encoder = new TextEncoder()

        for (const id in this.credentialTypes) {
            const data: Uint8Array<ArrayBuffer> = encoder.encode(id)

            const hashBuffer: ArrayBuffer = await crypto.subtle.digest("SHA-256", data)
            const hashArray = new Uint8Array(hashBuffer)

            // first 16 bytes of the SHA-256 of the id
            const truncated: Uint8Array<ArrayBuffer> = hashArray.subarray(0, 16)
            const strb64 = btoa(String.fromCharCode(...truncated))

            this.reverseHashes[strb64] = id
        }
    }

    /**
     * download and parse all of an issuer's public keys from the scheme host
     * and store them under publicKeys[issuerID]. grabs the scheme index, finds
     * every PublicKeys/N.xml entry for this issuer, then fetches and parses each one
     * @param issuerID - issuer whose keys we want to load
     * @returns resolves once the keys are fetched and stored
     */
    public async fetchPublicKeys(issuerID: IssuerIdentifier): Promise<void> {
        const schemeManagerID: SchemeManagerIdentifier = Identifier.parent(issuerID)
        const schemeManager: SchemeManager | undefined = this.schemeManagers[schemeManagerID]
        if (!schemeManager) {
            throw new Error(`SchemeManager not found: ${schemeManagerID}`)
        }

        const issuer: Issuer | undefined = this.issuers[issuerID]
        if (!issuer) {
            throw new Error(`Issuer not found: ${issuerID}`)
        }

        const baseURL = SCHEME_HOST_URL

        // fetch the scheme index listing every signed file in the scheme
        const indexURL = `${baseURL}/${schemeManager.id}/index`
        const indexResponse = await fetch(indexURL)
        if (!indexResponse.ok) {
            throw new Error(`Could not fetch index at ${indexURL}`)
        }
        const index = await indexResponse.text()

        // match every PublicKeys/N.xml entry for this scheme manager and issuer
        const regExp = new RegExp(`${schemeManager.id}/${issuer.id}/PublicKeys/[0-9]+\\.xml`, "g")

        const publicKeyRegExp: RegExpStringIterator<RegExpExecArray> = index.matchAll(regExp)
        const publicKeyNames: string[] = Array.from(publicKeyRegExp, (m) => m[0])
        const publicKeys: Record<number, PublicKey> = {}

        // download and parse each referenced public key
        for (let i = 0; i < publicKeyNames.length; i++) {
            const publicKeyURL = `${baseURL}/${publicKeyNames[i]}`
            const publicKeyResponse = await fetch(publicKeyURL)
            if (!publicKeyResponse.ok) {
                throw new Error(
                    `Could not fetch public key ${i} from ${schemeManager.id}.${issuer.id} at ${publicKeyURL}`
                )
            }
            const publicKeyData: string = await publicKeyResponse.text()

            const publicKey = xmlToPublicKey(publicKeyData)

            publicKey.issuer = issuerID

            publicKeys[publicKey.counter] = publicKey
        }
        // keep keys already loaded for other issuers
        if (this.publicKeys === undefined) {
            this.publicKeys = {}
        }
        this.publicKeys[issuerID] = publicKeys
    }

    /**
     * download and parse a credential type's description from the scheme host and
     * store it under credentialTypes[credentialTypeID].
     * also makes sure the parent scheme manager and issuer exist so a later
     * fetchPublicKeys for the same issuer can find them
     * @param credentialTypeID - credential type id, e.g. "irma-demo.gemeente.personalData"
     * @returns resolves once the credential type is fetched and stored
     */
    public async fetchCredentialType(credentialTypeID: CredentialTypeIdentifier): Promise<void> {
        const issuerID: IssuerIdentifier = Identifier.parent(credentialTypeID)
        const schemeManagerID: SchemeManagerIdentifier = Identifier.parent(issuerID)
        const issuerName: string = Identifier.name(issuerID)
        const credentialName: string = Identifier.name(credentialTypeID)

        // ensure the scheme manager and issuer exist for the later fetchPublicKeys
        if (!this.schemeManagers[schemeManagerID]) {
            this.schemeManagers[schemeManagerID] = new SchemeManager({
                id: schemeManagerID,
                status: "Valid",
            })
        }
        if (!this.issuers[issuerID]) {
            this.issuers[issuerID] = {
                id: issuerName,
                name: {},
                schemeManagerID: schemeManagerID,
                contactAddress: "",
                contactEMail: "",
                deprecatedSince: {
                    time: new Date(0),
                    serverURL: "",
                    sig: { alg: "", data: new Uint8Array(), publicKey: new Uint8Array() },
                },
                languages: [],
                xmlVersion: 0,
            }
        }

        const url = `${SCHEME_HOST_URL}/${schemeManagerID}/${issuerName}/Issues/${credentialName}/description.xml`
        const response = await fetch(url)
        if (!response.ok) {
            throw new Error(`Could not fetch credential type ${credentialTypeID} at ${url}`)
        }
        const xml = await response.text()

        this.credentialTypes[credentialTypeID] = xmlToCredentialType(
            xml,
            schemeManagerID,
            issuerName,
            credentialName
        )
    }
}

/**
 * parse an issuer <IssuerPublicKey> xml document into a PublicKey object
 * pulls out the idemix group elements (n, Z, S, optional G/H), the attribute
 * bases R, and picks the matching system parameters from the modulus bit length
 * @param xml - raw xml text of the public key file
 * @returns the parsed public key
 */
export function xmlToPublicKey(xml: string): PublicKey {
    const parser = new XMLParser({
        ignoreAttributes: false,
        removeNSPrefix: true,
        parseTagValue: false,
    })

    const result = parser.parse(xml)

    if (!result.IssuerPublicKey) {
        throw new Error("Invalid XML: missing <IssuerPublicKey>")
    }

    const pk = result.IssuerPublicKey
    const features = pk.Features
    const elements = pk.Elements
    const bases = elements.Bases

    const xmlName = { name: "http://www.zurich.ibm.com/security/idemix", space: "IssuerPublicKey" }
    const counter: number = Number(pk.Counter.valueOf())
    const expiryDate: number = Number(pk.ExpiryDate.valueOf())

    // group elements: modulus n, public values Z and S, optional G and H (revocation)
    const n: bigint = BigInt(elements.n.valueOf())
    const z: bigint = BigInt(elements.Z.valueOf())
    const s: bigint = BigInt(elements.S.valueOf())
    const g: bigint | undefined = elements.G ? BigInt(elements.G.valueOf()) : undefined
    const h: bigint | undefined = elements.H ? BigInt(elements.H.valueOf()) : undefined

    // bases R: read Base_0..Base_{num-1} explicitly, in attribute order
    const numBases: number = Number(bases["@_num"])
    if (!Number.isInteger(numBases) || numBases <= 0) {
        throw new Error('Invalid XML: <Bases> is missing a valid "num" attribute')
    }
    const r: bigint[] = []
    for (let i = 0; i < numBases; i++) {
        const base = bases[`Base_${i}`]
        if (base === undefined) {
            throw new Error(`Invalid XML: missing <Base_${i}>`)
        }
        r.push(BigInt(base as string))
    }
    const epochLength: number = Number(features.Epoch["@_length"].valueOf())
    const ecdsaString: string | undefined = pk.ECDSA

    // pick the standard system parameters matching the modulus bit length
    const bl: number = BigIntTool.bitLength(n)
    if (!(bl in DEFAULT_SYSTEM_PARAMETERS)) {
        throw new Error(`Non standard bit length: ${bl}`)
    }

    const params: SystemParameters = DEFAULT_SYSTEM_PARAMETERS[bl]!

    const publicKey = new PublicKey({
        xmlName: xmlName,
        counter: counter,
        expiryDate: expiryDate,
        n: n,
        z: z,
        s: s,
        g: g,
        h: h,
        r: r,
        epochLength: epochLength,
        ecdsaString: ecdsaString,
        params: params,
    })

    return publicKey
}

/**
 * parse a credential xml document into a CredentialType.
 * the attribute types are built in document order, which is the order the issuer
 * assigned the credential's attribute indices.
 * @param xml - raw xml text of the credential description
 * @param schemeManagerID - scheme this credential lives in, e.g. "irma-demo"
 * @param issuerID - issuer name, e.g. "gemeente"
 * @param credentialID - credential name, e.g. "personalData"
 * @returns the parsed credential type with its ordered attribute types
 */
export function xmlToCredentialType(
    xml: string,
    schemeManagerID: string,
    issuerID: string,
    credentialID: string
): CredentialType {
    const parser = new XMLParser({
        ignoreAttributes: false,
        removeNSPrefix: true,
        parseTagValue: false,
    })

    const result = parser.parse(xml)

    if (!result.IssueSpecification) {
        throw new Error("Invalid XML: missing <IssueSpecification>")
    }

    const attributes = result.IssueSpecification.Attributes
    if (!attributes || attributes.Attribute === undefined) {
        throw new Error(`Invalid credential description for ${credentialID}: missing <Attributes>`)
    }

    // fast-xml-parser yields a single object when there is exactly one attribute
    const rawAttributes: Record<string, unknown>[] = Array.isArray(attributes.Attribute)
        ? attributes.Attribute
        : [attributes.Attribute]

    // document order is the cryptographic attribute order, so keep the array order
    const attributeTypes: AttributeType[] = rawAttributes.map(
        (attribute, index) =>
            new AttributeType({
                id: String(attribute["@_id"]),
                optional:
                    attribute["@_optional"] !== undefined
                        ? String(attribute["@_optional"])
                        : undefined,
                displayIndex:
                    attribute["@_displayIndex"] !== undefined
                        ? Number(attribute["@_displayIndex"])
                        : undefined,
                displayHint:
                    attribute["@_displayHint"] !== undefined
                        ? String(attribute["@_displayHint"])
                        : undefined,
                randomBlind: attribute["@_random_blind"] === "true" || undefined,
                index: index,
                credentialTypeID: credentialID,
                issuerID: issuerID,
                schemeManagerID: schemeManagerID,
            })
    )

    return new CredentialType({
        id: credentialID,
        issuerID: issuerID,
        schemeManagerID: schemeManagerID,
        attributeTypes: attributeTypes,
    })
}


type ConfigurationListener = (conf: Configuration) => void

/**
 * options controlling how a configuration is initialized,
 * whether it is read only, and how revocation is wired up
 */
export class ConfigurationOptions {
    assets: string
    readOnly: boolean
    ignorePrivateKeys: boolean
    revocationDBConnStr: string
    revocationDBType: string
    revocationSettings?: RevocationSettings

    constructor({
        assets = "",
        readOnly = false,
        ignorePrivateKeys = false,
        revocationDBConnStr = "",
        revocationDBType = "",
        revocationSettings,
    }: Partial<ConfigurationOptions> = {}) {
        this.assets = assets
        this.readOnly = readOnly
        this.ignorePrivateKeys = ignorePrivateKeys
        this.revocationDBConnStr = revocationDBConnStr
        this.revocationDBType = revocationDBType
        this.revocationSettings = revocationSettings
    }
}
