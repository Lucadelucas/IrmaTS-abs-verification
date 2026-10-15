import { BigIntTool } from "./internal/common/mathutil.ts"
import * as gabikeys from "./gabikeys/keys"
import { Sha256, Encoding } from "./internal/common/hashtool.ts"
import * as revocation from "./revocation/proof.ts"

/**
 * JSON shape of a single disclosure proof, with the big integers base64 encoded
 * and keyed by attribute index
 */
export type ProofDJSON = {
    c: string
    A: string
    e_response: string
    v_response: string
    a_responses: Record<string, string>
    a_disclosed: Record<string, string>
}

/**
 * disclosure proof produced in the showing protocol
 *
 * it carries the prover's commitment, responses and the attributes that were
 * actually revealed. the same structure is used when disclosing attributes
 * after a successful verification.
 */
export class ProofD {
    c: bigint               // the challenge the prover answered
    a: bigint               // randomised version of the signature value A
    eResponse: bigint       // response for the e part of the signature
    vResponse: bigint       // response for the v (blinding) part
    aResponses: Record<number, bigint>  // responses for the hidden attributes, keyed by index
    aDisclosed: Record<number, bigint>  // attributes that were revealed, keyed by index
    nonRevocationProof?: revocation.Proof   // optional proof that the credential isn't revoked

    /**
     * build a proof, defaulting any field that wasn't supplied
     * @param fields partial set of proof fields, anything missing falls back to a sensible default
     */
    constructor({
        c = 0n,
        a = 0n,
        eResponse = 0n,
        vResponse = 0n,
        aResponses = {},
        aDisclosed = {},
        nonRevocationProof = undefined,
    }: Partial<ProofD>) {
        this.c = c
        this.a = a
        this.eResponse = eResponse
        this.vResponse = vResponse
        this.aResponses = aResponses
        this.aDisclosed = aDisclosed
        this.nonRevocationProof = nonRevocationProof
    }

    /**
     * build a ProofD from its JSON form, failing closed when an essential field
     * is missing. a_responses must carry index 0 (the secret-key response) and
     * a_disclosed must carry index 1 (the metadata attribute), since the rest of
     * verification relies on both being present.
     * @param proof the proof JSON, either as a string or an already parsed object
     * @returns the decoded ProofD
     */
    static fromJSON(proof: string | ProofDJSON): ProofD {
        const parsed: ProofDJSON = typeof proof === "string" ? JSON.parse(proof) : proof

        for (const field of ["c", "A", "e_response", "v_response"] as const) {
            if (typeof parsed[field] !== "string" || parsed[field].length === 0) {
                throw new Error(`Invalid proof: missing or empty field "${field}"`)
            }
        }
        if (parsed.a_responses === null || typeof parsed.a_responses !== "object") {
            throw new Error('Invalid proof: missing "a_responses"')
        }
        if (parsed.a_disclosed === null || typeof parsed.a_disclosed !== "object") {
            throw new Error('Invalid proof: missing "a_disclosed"')
        }
        if (parsed.a_responses["0"] === undefined) {
            throw new Error('Invalid proof: "a_responses" lacks the secret-key response at index 0')
        }
        if (parsed.a_disclosed["1"] === undefined) {
            throw new Error('Invalid proof: "a_disclosed" lacks the metadata attribute at index 1')
        }

        const c: bigint = Encoding.base64ToBigInt(parsed.c)
        const a: bigint = Encoding.base64ToBigInt(parsed.A)
        const eResponse: bigint = Encoding.base64ToBigInt(parsed.e_response)
        const vResponse: bigint = Encoding.base64ToBigInt(parsed.v_response)
        const aResponses: Record<number, bigint> = Object.fromEntries(
            Object.entries(parsed.a_responses).map(([k, v]) => [Number(k), Encoding.base64ToBigInt(v)])
        )
        const aDisclosed: Record<number, bigint> = Object.fromEntries(
            Object.entries(parsed.a_disclosed).map(([k, v]) => [Number(k), Encoding.base64ToBigInt(v)])
        )

        return new ProofD({ c, a, eResponse, vResponse, aResponses, aDisclosed })
    }

    /**
     * check the proof against a challenge we recomputed ourselves
     *
     * the proof is valid when the responses are within their expected bit sizes
     * and the challenge stored in the proof matches the one we reconstructed. if
     * they differ, the prover didn't actually know the secrets.
     * @param _pk public key the proof was made under
     * @param reconstructedChallenge challenge value recomputed from the proof
     * @returns true if the proof verifies
     */
    public verifyWithChallenge(_pk: gabikeys.PublicKey, reconstructedChallenge: bigint): boolean {
        // TODO actually check non-revocation
        const notrevoked: boolean = true

        return notrevoked && this.correctResponseSizes(_pk) && this.c === reconstructedChallenge
    }

    /**
     * make sure every response fits the bit size it's supposed to
     *
     * a response that's too large is a sign the proof was tampered with, so we
     * reject anything outside the allowed range. attribute responses must fit
     * 2^(lmCommit+1)-1 and the e-response must fit 2^(leCommit+1)-1.
     * @param pk public key whose system parameters define the bounds
     * @returns true if all responses are within range
     */
    private correctResponseSizes(pk: gabikeys.PublicKey): boolean {
        const minimum: bigint = 0n
        // attribute response bound: 2^(lmCommit + 1) - 1
        let maximum: bigint = (1n << BigInt(pk.params.lmCommit + 1)) - 1n
        for (const aResponse of Object.values(this.aResponses)) {
            if (aResponse < minimum || aResponse > maximum) {
                return false
            }
        }

        // e-response bound: 2^(leCommit + 1) - 1
        maximum = (1n << BigInt(pk.params.leCommit + 1)) - 1n

        return this.eResponse >= minimum && this.eResponse <= maximum
    }

    /**
     * rebuild the commitment Z from the proof and the public key
     *
     * if the prover was honest this lands on the same Z they committed to, which
     * is what makes the challenge match later. the formula is
     * Z = known^-c * a^eResponse * prod_i R_i^aResponses[i] * S^vResponse mod N
     * @param pk public key the proof was made under
     * @returns the reconstructed Z value mod N
     */
    public async reconstructZ(pk: gabikeys.PublicKey): Promise<bigint> {
        // known folds in everything we already know: the disclosed attributes
        // and the fixed a^(2^(le-1)) offset, so
        // known = z / ( prod_disclosed R_i^a_i * a^(2^(le-1)) )

        // start the numerator at a^(2^(le-1)) mod N
        let numerator = 1n << (BigInt(pk.params.le) - 1n)
        numerator = BigIntTool.modExp(this.a, numerator, pk.n)

        // then multiply in R_i^a_i for every disclosed attribute
        for (const [i, attribute] of Object.entries(this.aDisclosed)) {
            let exp = BigInt(attribute)

            // attributes longer than lm bits are hashed down so they stay in range
            if (BigIntTool.bitLength(exp) > Number(pk.params.lm))
                exp = await Sha256.bigIntToBigInt(exp)

            const term = BigIntTool.modExp(pk.r[Number(i)]!, exp, pk.n)
            numerator = BigIntTool.modMult([numerator, term], pk.n)
        }

        // known = z * numerator^-1 mod N, i.e. divide z by everything we just built up
        let invNum: bigint
        try {
            invNum = BigIntTool.modInv(numerator, pk.n)
        } catch (e) {
            throw new Error("no modular inverse for numerator of known", { cause: e })
        }
        const known = BigIntTool.modMult([pk.z, invNum], pk.n)

        // raise known to -c so it cancels the challenge term, knownC = known^-c mod N
        let invKnown: bigint
        try {
            invKnown = BigIntTool.modInv(known, pk.n)
        } catch (e) {
            throw new Error("no modular inverse for knownC", { cause: e })
        }
        const knownC = BigIntTool.modExp(invKnown, this.c, pk.n)

        // ae = a^eResponse mod N
        const ae = BigIntTool.modExp(this.a, this.eResponse, pk.n)

        // Sv = S^vResponse mod N
        const Sv = BigIntTool.modExp(pk.s, this.vResponse, pk.n)

        // Rs collects R_i^aResponses[i] for every hidden attribute
        let Rs = 1n
        for (const [i, response] of Object.entries(this.aResponses)) {
            const t = BigIntTool.modExp(pk.r[Number(i)]!, response, pk.n)
            Rs = BigIntTool.modMult([Rs, t], pk.n)
        }

        // multiply the four pieces together to get Z = knownC * ae * Rs * Sv mod N
        return BigIntTool.modMult([knownC, ae, Rs, Sv], pk.n)
    }

    /**
     * give this proof's slice of the data that feeds the challenge hash
     *
     * the verifier hashes the contributions of every proof together and compares
     * the result to the stored challenge, so each proof has to hand over the same
     * [a, z] pair the prover used.
     * @param pk public key the proof was made under
     * @returns the [a, z] pair contributed to the hash
     */
    public async challengeContribution(pk: gabikeys.PublicKey): Promise<bigint[]> {
        const z: bigint = await this.reconstructZ(pk)

        const l: bigint[] = [this.a, z]
        // TODO: non-revocation contributions should be appended yet

        return l
    }

    /**
     * response tied to the secret key, which lives at attribute index 0
     * @returns the response for attribute index 0
     */
    secretKeyResponse(): bigint {
        return this.aResponses[0]!
    }
}
