import * as proofs from "./proofs"
import * as gabikeys from "./gabikeys/keys"
import * as commonHashTool from "./internal/common/hashtool"

/**
 * a bundle of disclosure proofs that all get verified against one shared challenge.
 * grouping them like this is what lets us check that proofs which belong together
 * actually use the same secret key
 */
export class ProofList {
    proofList: proofs.ProofD[] // the disclosure proofs being wrapped

    /**
     * @param proofList - the disclosure proofs to verify together
     */
    constructor(proofList: proofs.ProofD[]) {
        this.proofList = proofList
    }

    /**
     * gather every proof's challenge contribution and flatten them into one list,
     * keeping list order so the values stay lined up with their proofs
     * @param publickKeys - public key per proof, matched by index
     * @returns the concatenated contributions of all proofs
     */
    async challengeContribution(publickKeys: gabikeys.PublicKey[]): Promise<bigint[]> {
        let contributions: bigint[] = []
        for (let i = 0; i < this.proofList.length; i++) {
            // each proof contributes under its own public key
            const proof: proofs.ProofD = this.proofList[i]!
            const contrib: bigint[] = await proof.challengeContribution(publickKeys[i]!)
            contributions = contributions.concat(contrib)
        }
        return contributions
    }

    /**
     * verify every proof against the rebuilt challenge and make sure the secret-key
     * responses line up.
     *
     * the idea: proofs that share a keyshare server (or use none) are about the same
     * secret key, so their secret-key responses have to be equal. an empty list is
     * always invalid, and anything that throws along the way is treated as a failure.
     *
     * @param publicKeys - public key per proof, matched by index
     * @param context - the verification context value
     * @param nonce - the verifier's nonce
     * @param keyshareServers - keyshare server per proof; an empty array means none/shared
     * @returns true if all proofs verify and the secret-key responses are consistent
     */
    async verify(
        publicKeys: gabikeys.PublicKey[],
        context: bigint,
        nonce: bigint,
        keyshareServers: string[]
    ): Promise<boolean> {
        // reject empty list and length mismatches across proofs, keys, keyshare servers
        if (
            this.proofList.length === 0 ||
            this.proofList.length != publicKeys.length ||
            (keyshareServers.length > 0 && this.proofList.length != keyshareServers.length)
        ) {
            return false
        }

        // remembers the secret-key response we saw for each keyshare server, so later
        // proofs under the same server can be checked against it
        const secretKeyResponses: Record<string, bigint> = {}

        try {
            const contributions: bigint[] = await this.challengeContribution(publicKeys)

            const expectedChallenge: bigint = await createChallenge(context, contributions, nonce)

            // when no keyshare servers are given this stays "", so every proof ends up
            // in the same bucket and they all get compared against each other
            let kss: string = ""

            for (const [key, proof] of Object.entries(this.proofList)) {
                const i = Number(key)
                // each proof must verify against the shared challenge under its key
                if (!proof.verifyWithChallenge(publicKeys[i]!, expectedChallenge)) {
                    return false
                }
                // pick the keyshare server bucket for this proof, if any
                if (keyshareServers.length > 0) {
                    kss = keyshareServers[i]!
                }

                if (secretKeyResponses[kss] === undefined) {
                    secretKeyResponses[kss] = proof.secretKeyResponse()
                } else {
                    // seen this keyshare server; response must match the earlier one
                    if (secretKeyResponses[kss] !== proof.secretKeyResponse()) {
                        return false
                    }
                }
            }
        } catch {
            return false
        }
        return true
    }
}

/**
 * hash the context, all the contributions and the nonce together into the single
 * challenge value that every proof in the list is checked against
 * @param context - the verification context value
 * @param contributions - the flattened challenge contributions of all proofs
 * @param nonce - the verifier's nonce
 * @returns the shared challenge
 */
export async function createChallenge(
    context: bigint,
    contributions: bigint[],
    nonce: bigint
): Promise<bigint> {
    const input: bigint[] = [context, ...contributions, nonce]
    return await commonHashTool.hashCommit(input)
}
