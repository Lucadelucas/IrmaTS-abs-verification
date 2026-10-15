import { CredentialIdentifier } from "./identifiers.ts"
import * as gabilist from "../gabi/prooflist.ts"
import * as gabi from "../gabi/proofs.ts"
import { AttributeConDisCon } from "./requests.ts"
import { ATTRIBUTE_PROOF_STATUS_EXTRA, DisclosedAttribute, extractAttribute } from "./verify.ts"
import { Configuration } from "./irmaconfig.ts"

/**
 * irma protocol version as a major/minor pair
 */
export class ProtocolVersion {
    Major: number
    Minor: number

    /**
     * @param Major - major version number
     * @param Minor - minor version number
     */
    constructor(Major: number, Minor: number) {
        this.Major = Major
        this.Minor = Minor
    }
}


export interface Validator {
    validate(): void
}

/**
 * a disclosure: the proofs together with the indices that say which
 * attributes inside those proofs are actually revealed
 */
export class Disclosure {
    proofs: gabilist.ProofList
    indices: DisclosedAttributeIndices

    /**
     * @param proofs - the proof list backing this disclosure
     * @param indices - per request conjunction, which attributes are disclosed
     */
    constructor(proofs: gabilist.ProofList, indices: DisclosedAttributeIndices) {
        this.proofs = proofs
        this.indices = indices
    }

    /**
     * finds disclosed attributes that aren't claimed by any part of the request.
     * these are the "extra" attributes the prover revealed on top of what was asked
     * @param condiscon - the requested condiscon structure
     * @returns indices of the surplus disclosed attributes
     */
    private extraIndices(condiscon: AttributeConDisCon): DisclosedAttributeIndex[] {
        const disclosed: Set<number>[] = Array<Set<number>>(this.proofs.proofList.length)

        // record every disclosed index per proof, skipping 0 (metadata) and 1 (secret key)
        for (let i = 0; i < this.proofs.proofList.length; i++) {
            const proofd: gabi.ProofD = this.proofs.proofList[i] as gabi.ProofD

            disclosed[i] = new Set<number>()
            for (const key in proofd.aDisclosed) {
                const j = Number(key)
                if (j <= 1) {
                    continue
                }
                disclosed[i]?.add(j)
            }
        }

        // drop the indices claimed by the request, leaving only the surplus
        for (let i = 0; i < this.indices.length; i++) {
            if (condiscon.attributeConDisCon.length <= i) {
                continue
            }
            for (const index of this.indices[i]!) {
                disclosed[index.credentialIndex]?.delete(index.attributeIndex)
            }
        }

        const extra: DisclosedAttributeIndex[] = []
        for (let i = 0; i < disclosed.length; i++) {
            for (const j of disclosed[i]!) {
                extra.push({
                    credentialIndex: i,
                    attributeIndex: j,
                    identifier: new CredentialIdentifier({}),
                })
            }
        }
        return extra
    }

    /**
     * builds the list of disclosed attributes per request conjunction and appends
     * any extra attributes that were revealed but not requested
     * @param configuration - scheme configuration used to interpret attributes
     * @param condiscon - the requested condiscon structure
     * @param revtimes - revocation timestamps keyed by credential index
     * @returns [allDisjunctionsSatisfied, disclosedAttributesPerConjunction]
     */
    protected disclosedAttributes(
        configuration: Configuration,
        condiscon: AttributeConDisCon,
        revtimes: Record<number, Date>
    ): [boolean, DisclosedAttribute[][] | undefined] {
        const [complete, list] = condiscon.satisfy(this, revtimes, configuration)

        // extract attributes disclosed beyond the request and mark them EXTRA
        const extra: DisclosedAttribute[] = []
        const indices: DisclosedAttributeIndex[] = this.extraIndices(condiscon)

        for (const index of indices) {
            const [attr, _str]: [DisclosedAttribute, string] = extractAttribute(
                this.proofs,
                index,
                revtimes[index.credentialIndex]!,
                configuration
            )
            attr.status = ATTRIBUTE_PROOF_STATUS_EXTRA
            extra.push(attr)
        }
        // if satisfy() returned undefined for list, optional chaining drops the extras
        if (extra.length > 0) {
            list?.push(extra)
        }

        return [complete, list]
    }
}

/**
 * disclosed attribute indices grouped per request conjunction.
 * outer array follows the condiscon disjunctions, inner array the picked attributes
 */
export type DisclosedAttributeIndices = DisclosedAttributeIndex[][]

/**
 * points to a single attribute within a proof list
 */
export type DisclosedAttributeIndex = {
    credentialIndex: number
    attributeIndex: number
    identifier: CredentialIdentifier
}

/**
 * session type (e.g. disclosing, signing, issuing)
 */
export type Action = string
