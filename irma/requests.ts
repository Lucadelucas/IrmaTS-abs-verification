import {
    AttributeTypeIdentifier,
    CredentialTypeIdentifier,
    IrmaIdentifierSet,
} from "./identifiers.ts"
import { TranslatedString } from "./descriptions.ts"
import { Configuration } from "./irmaconfig.ts"
import { DisclosedAttribute, extractAttribute } from "./verify.ts"
import * as gabiList from "../gabi/prooflist.ts"
import { Action, DisclosedAttributeIndex, ProtocolVersion, Validator } from "./messages.ts"
import * as messages from "./messages.ts"
import { Timestamp } from "./timestamp.ts"

/**
 * fields shared by every irma session request, more specific request types
 * extend this with their own extra fields
 */
class BaseRequest {
    LDContext: string
    Context?: bigint
    Nonce?: bigint
    ProtocolVersion?: ProtocolVersion
    Revocation: NonRevocationParameters
    ids?: IrmaIdentifierSet // cached identifier set so we don't recompute it
    legacy: boolean // true if this came from an old pre-condiscon request format
    Type: Action
    DevelopmentMode: boolean
    ClientReturnURL: string // url to send the user to once the session finishes
    AugmentReturnURL: boolean // tack the session token onto the return url
    Host: string // host shown in the session qr code

    /**
     * @param LDContext json-ld context string
     * @param Context session context value
     * @param Nonce session nonce
     * @param ProtocolVersion protocol version of the request
     * @param Revocation per-credential non-revocation requirements
     * @param ids cached set of identifiers used by this request
     * @param legacy whether this was a legacy-format request
     * @param Type the session action
     * @param DevelopmentMode whether dev mode is on
     * @param ClientReturnURL url to return to after the session
     * @param AugmentReturnURL whether to append the session token to the return url
     * @param Host host used in the session qr
     */
    constructor(
        LDContext: string,
        Context: bigint,
        Nonce: bigint,
        ProtocolVersion: ProtocolVersion,
        Revocation: NonRevocationParameters,
        ids: IrmaIdentifierSet,
        legacy: boolean,
        Type: Action,
        DevelopmentMode: boolean,
        ClientReturnURL: string,
        AugmentReturnURL: boolean,
        Host: string
    ) {
        this.LDContext = LDContext
        this.Context = Context
        this.Nonce = Nonce
        this.ProtocolVersion = ProtocolVersion
        this.Revocation = Revocation
        this.ids = ids
        this.legacy = legacy
        this.Type = Type
        this.DevelopmentMode = DevelopmentMode
        this.ClientReturnURL = ClientReturnURL
        this.AugmentReturnURL = AugmentReturnURL
        this.Host = Host
    }

    /**
     * returns the context value, falling back to 1 when it was never set
     * @returns the context, or 1 if undefined
     */
    public getContext(): bigint {
        if (this.Context === undefined) {
            return BigInt(1)
        }
        return this.Context
    }
}

/**
 * an "and" over attribute requests: every request in it has to match for the
 * whole conjunction to be satisfied
 */
export class AttributeCon {
    attributeCon: AttributeRequest[]

    /**
     * @param attributeCon the attribute requests, defaults to empty
     */
    constructor(attributeCon?: AttributeRequest[]) {
        this.attributeCon = attributeCon ?? []
    }

    /**
     * checks the disclosure against every request in this conjunction.
     * note the three-way result: null means "empty conjunction" which counts as
     * satisfied, undefined means it didn't match, and an array means it did
     * @param proofs the proof list from the disclosure
     * @param indices which attribute each proof discloses
     * @param revocation revocation timestamps keyed by credential index
     * @param conf the active configuration
     * @returns the disclosed attributes, null if empty, or undefined if not satisfied
     */
    public satisfy(
        proofs: gabiList.ProofList,
        indices: DisclosedAttributeIndex[],
        revocation: Record<number, Date>,
        conf: Configuration
    ): DisclosedAttribute[] | null | undefined {
        if (indices.length < this.attributeCon.length) {
            return undefined
        }
        // an empty conjunction is a trivially-satisfied optional disjunction member
        if (this.attributeCon.length === 0) {
            return null
        }

        const attrs: DisclosedAttribute[] = []
        for (let k = 0; k < this.attributeCon.length; k++) {
            const index: DisclosedAttributeIndex = indices[k]!
            const [attr, val]: [DisclosedAttribute, string] = extractAttribute(
                proofs,
                index,
                revocation[index.credentialIndex]!,
                conf
            )
            if (!this.attributeCon[k]!.satisfy(attr.identifier, val)) {
                return undefined
            }
            attrs.push(attr)
        }
        return attrs
    }
}

/**
 * an "or" over conjunctions: the user only needs to satisfy one of the
 * conjunctions for this disjunction to pass
 */
export class AttributeDisCon {
    attributeDisCon: AttributeCon[]

    /**
     * @param attributeDisCon the conjunctions to choose between, defaults to empty
     */
    constructor(attributeDisCon?: AttributeCon[]) {
        this.attributeDisCon = attributeDisCon ?? []
    }

    /**
     * tries each conjunction in order and returns the first one that matches
     * @param proofs the proof list from the disclosure
     * @param indices which attribute each proof discloses
     * @param revocation revocation timestamps keyed by credential index
     * @param conf the active configuration
     * @returns the matching conjunction's attributes, or undefined if none match
     */
    public satisfy(
        proofs: gabiList.ProofList,
        indices: DisclosedAttributeIndex[],
        revocation: Record<number, Date>,
        conf: Configuration
    ): DisclosedAttribute[] | null | undefined {
        for (const con of this.attributeDisCon) {
            const attrs = con.satisfy(proofs, indices, revocation, conf)
            if (attrs !== undefined) {
                return attrs
            }
        }
        return undefined
    }
}

/**
 * the top-level shape of a request: an "and" of "or"s. every disjunction has to
 * be satisfied, and each disjunction offers a few conjunctions to pick from
 */
export class AttributeConDisCon {
    attributeConDisCon: AttributeDisCon[]

    /**
     * @param attribute the disjunctions making up the request, defaults to empty
     */
    constructor(attribute?: AttributeDisCon[]) {
        this.attributeConDisCon = attribute ?? []
    }

    /**
     * walks every disjunction and collects the disclosed attributes per slot.
     * slots that couldn't be satisfied are left undefined, and the boolean tells
     * you whether all of them passed
     * @param disclosure the disclosure being checked
     * @param revocation revocation timestamps keyed by credential index
     * @param conf the active configuration
     * @returns a pair of [whether everything matched, attributes per disjunction]
     */
    public satisfy(
        disclosure: messages.Disclosure,
        revocation: Record<number, Date>,
        conf: Configuration
    ): [boolean, DisclosedAttribute[][] | undefined] {
        if (disclosure.indices.length < this.attributeConDisCon.length) {
            return [false, undefined]
        }
        const list = Array(this.attributeConDisCon.length)
        let complete: boolean = true

        for (let i = 0; i < this.attributeConDisCon.length; i++) {
            const discon: AttributeDisCon = this.attributeConDisCon[i]!
            const attrs: DisclosedAttribute[] | null | undefined = discon.satisfy(
                disclosure.proofs,
                disclosure.indices[i]!,
                revocation,
                conf
            )

            if (attrs === undefined) {
                complete = false
                list[i] = undefined
            } else {
                list[i] = attrs
            }
        }
        return [complete, list]
    }
}

/**
 * a request asking the user to disclose a set of attributes, described by the
 * condiscon in Disclose
 */
class DisclosureRequest extends BaseRequest {
    Disclose: AttributeConDisCon
    Labels: Record<number, TranslatedString>

    SkipExpiryCheck: CredentialTypeIdentifier[] // credential types whose expiry we don't enforce

    /**
     * @param Disclose the condiscon describing what to disclose
     * @param Labels human-readable labels keyed by disjunction index
     * @param SkipExpiryCheck credential types exempt from the expiry check
     * @param LDContext json-ld context string
     * @param Context session context value
     * @param Nonce session nonce
     * @param ProtocolVersion protocol version of the request
     * @param Revocation per-credential non-revocation requirements
     * @param ids cached set of identifiers used by this request
     * @param legacy whether this was a legacy-format request
     * @param Type the session action
     * @param DevelopmentMode whether dev mode is on
     * @param ClientReturnURL url to return to after the session
     * @param AugmentReturnURL whether to append the session token to the return url
     * @param Host host used in the session qr
     */
    constructor(
        LDContext: string,
        Context: bigint,
        Nonce: bigint,
        ProtocolVersion: ProtocolVersion,
        Revocation: NonRevocationParameters,
        ids: IrmaIdentifierSet,
        legacy: boolean,
        Type: Action,
        DevelopmentMode: boolean,
        ClientReturnURL: string,
        AugmentReturnURL: boolean,
        Host: string,
        Disclose: AttributeConDisCon,
        Labels: Record<number, TranslatedString>,
        SkipExpiryCheck: CredentialTypeIdentifier[]
    ) {
        super(
            LDContext,
            Context,
            Nonce,
            ProtocolVersion,
            Revocation,
            ids,
            legacy,
            Type,
            DevelopmentMode,
            ClientReturnURL,
            AugmentReturnURL,
            Host
        )
        this.Disclose = Disclose
        this.Labels = Labels
        this.SkipExpiryCheck = SkipExpiryCheck
    }
}

/**
 * a disclosure request that also signs a message, so the user attests to the
 * Message string on top of disclosing attributes
 */
export class SignatureRequest extends DisclosureRequest implements SessionRequest {
    Message: string // the message the user signs

    /**
     * @param Message the message to be signed
     * @param Disclose the condiscon describing what to disclose
     * @param Labels human-readable labels keyed by disjunction index
     * @param SkipExpiryCheck credential types exempt from the expiry check
     * @param LDContext json-ld context string
     * @param Context session context value
     * @param Nonce session nonce
     * @param ProtocolVersion protocol version of the request
     * @param Revocation per-credential non-revocation requirements
     * @param ids cached set of identifiers used by this request
     * @param legacy whether this was a legacy-format request
     * @param Type the session action
     * @param DevelopmentMode whether dev mode is on
     * @param ClientReturnURL url to return to after the session
     * @param AugmentReturnURL whether to append the session token to the return url
     * @param Host host used in the session qr
     */
    constructor(
        LDContext: string,
        Context: bigint,
        Nonce: bigint,
        ProtocolVersion: ProtocolVersion,
        Revocation: NonRevocationParameters,
        ids: IrmaIdentifierSet,
        legacy: boolean,
        Type: Action,
        DevelopmentMode: boolean,
        ClientReturnURL: string,
        AugmentReturnURL: boolean,
        Host: string,
        Disclose: AttributeConDisCon,
        Labels: Record<number, TranslatedString>,
        SkipExpiryCheck: CredentialTypeIdentifier[],
        Message: string
    ) {
        super(
            LDContext,
            Context,
            Nonce,
            ProtocolVersion,
            Revocation,
            ids,
            legacy,
            Type,
            DevelopmentMode,
            ClientReturnURL,
            AugmentReturnURL,
            Host,
            Disclose,
            Labels,
            SkipExpiryCheck
        )
        this.Message = Message
    }

    validate(): void {
        throw new Error("Method not implemented.")
    }

    base(): BaseRequest {
        throw new Error("Method not implemented.")
    }

    disclosure(): DisclosureRequest {
        throw new Error("Method not implemented.")
    }

    identifiers(): IrmaIdentifierSet {
        throw new Error("Method not implemented.")
    }

    action(): Action {
        throw new Error("Method not implemented.")
    }
}

/**
 * common interface every irma session request implements, giving callers a
 * uniform way to get at the base, disclosure, identifiers and action
 */
export interface SessionRequest extends Validator {
    base(): BaseRequest

    disclosure(): DisclosureRequest

    identifiers(): IrmaIdentifierSet

    action(): Action
}

/**
 * the leaf of a conjunction: asks for one attribute type, optionally requiring a
 * specific value or just requiring it to be present
 */
export class AttributeRequest {
    type: AttributeTypeIdentifier
    value: string
    notNull: boolean

    /**
     * @param type the attribute type being requested
     * @param value the value it must equal, if pinned
     * @param notNull whether the attribute is required to be present
     */
    constructor(type: AttributeTypeIdentifier, value: string, notNull: boolean) {
        this.type = type
        this.value = value
        this.notNull = notNull
    }

    /**
     * decides whether a disclosed attribute satisfies this request. the type has
     * to match, and if notNull or a pinned value is set the disclosed value has
     * to back that up
     * @param attr the disclosed attribute type
     * @param val the disclosed value, or undefined if not revealed
     * @returns true if the disclosure satisfies this request
     */
    public satisfy(attr: AttributeTypeIdentifier, val: string|undefined): boolean {
        return (
            this.type === attr &&
            (!this.notNull || val !== undefined) &&
            (this.value === undefined || (val !== undefined && val === this.value))
        )
    }
}

/**
 * non-revocation requirement for a single credential type. Tolerance is how
 * stale (in seconds) the revocation info is allowed to be
 */
type NonRevocationRequest = {
    Tolerance: number
    //TODO Updates: Record<number, revocation.Update>
}

/** non-revocation requirements per credential type, keyed by credential id */
export type NonRevocationParameters = Map<CredentialTypeIdentifier, NonRevocationRequest>

export { Timestamp }
