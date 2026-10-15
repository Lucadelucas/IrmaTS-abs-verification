/**
 * small helpers for working with dotted identifier strings like
 * "irma-demo.RU.studentCard", where each "." separates a level in the hierarchy
 */
export namespace Identifier {
    /**
     * grabs the parent part of a dotted id, i.e. everything before the last "."
     * if there's no "." the id has no parent so we just hand it back unchanged
     * @param id the dotted identifier
     * @returns the parent portion, or the whole id if there's no dot
     */
    export function parent(id: MetaObjectIdentifier): string {
        const i = id.lastIndexOf(".")
        if (i !== -1) {
            return id.substring(0, i)
        } else {
            return id
        }
    }

    /**
     * grabs the last segment of a dotted id, i.e. everything after the last "."
     * with no "." present the whole string is the name
     * @param id the dotted identifier
     * @returns the final segment, or the whole id if there's no dot
     */
    export function name(id: MetaObjectIdentifier): string {
        const i: number = id.lastIndexOf(".")
        if (i !== -1) {
            return id.substring(i + 1)
        } else {
            return id
        }
    }
}

/**
 * base type for every dotted IRMA identifier, it's just a string underneath
 * the named aliases below all resolve to this, they only exist to make the
 * code more readable about which kind of identifier is expected where
 */
type MetaObjectIdentifier = string

/** a requestor scheme, the id equals the scheme's own name (e.g. "pbdf-requestors") */
export type RequestorSchemeIdentifier = MetaObjectIdentifier

/** a single requestor living inside a requestor scheme */
export type RequestorIdentifier = MetaObjectIdentifier

/** an issue wizard */
export type IssueWizardIdentifier = MetaObjectIdentifier

/** a scheme manager, the id equals its own name (e.g. "irma-demo") */
export type SchemeManagerIdentifier = MetaObjectIdentifier

/** an issuer, scheme manager plus issuer name (e.g. "irma-demo.RU") */
export type IssuerIdentifier = MetaObjectIdentifier

/** a credential type, issuer plus credential name (e.g. "irma-demo.RU.studentCard") */
export type CredentialTypeIdentifier = MetaObjectIdentifier

/**
 * an attribute type, credential type plus attribute name
 * (e.g. "irma-demo.RU.studentCard.studentID")
 */
export type AttributeTypeIdentifier = MetaObjectIdentifier

/**
 * points at one concrete credential instance: which credential type it is,
 * plus the hash that uniquely identifies this particular instance
 */
export class CredentialIdentifier {
    type: CredentialTypeIdentifier
    hash: string

    /**
     * builds a credential identifier from a partial object, both fields
     * default to "" so you can pass just the parts you care about
     * @param type the credential type
     * @param hash the instance hash
     */
    constructor({ type = "", hash = "" }: Partial<CredentialIdentifier>) {
        this.type = type
        this.hash = hash
    }
}

/**
 * points at one attribute on a specific credential instance: the attribute
 * type plus the hash of the credential instance it belongs to
 */
export type AttributeIdentifier = {
    type: AttributeTypeIdentifier
    credentialHash: string
}

/**
 * the full set of identifiers touched in a session, used to know which scheme
 * data needs to be loaded. publicKeys maps each issuer to the public key
 * counter (key version) it uses, the rest are plain sets of what was referenced
 */
export type IrmaIdentifierSet = {
    schemeManagers: Set<SchemeManagerIdentifier>
    issuers: Set<IssuerIdentifier>
    credentialTypes: Set<CredentialTypeIdentifier>
    publicKeys: Map<IssuerIdentifier, number> // issuer -> public key counter
    attributeTypes: Set<AttributeTypeIdentifier>
    requestorSchemes: Set<RequestorSchemeIdentifier>
}
