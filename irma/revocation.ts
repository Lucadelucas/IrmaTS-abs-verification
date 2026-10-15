import { CredentialTypeIdentifier, IssuerIdentifier } from "./identifiers.ts"
import { Configuration } from "./irmaconfig.ts"
import * as gabikeys from "../gabi/gabikeys/keys.ts"

/**
 * holds the revocation data we need while verifying a signature.
 * currently empty since the verification path only needs the key lookup below,
 * but it stays here as the place to hang revocation state if more is needed later.
 */
export class RevocationStorage {
}

/**
 * looks up revocation public keys from a loaded configuration.
 */
export class RevocationKeys {
    Conf?: Configuration

    /**
     * @param conf configuration to pull public keys out of
     */
    constructor(conf: Configuration) {
        this.Conf = conf
    }

    /**
     * fetches the revocation-capable public key for a given issuer and key counter.
     * keys are versioned by counter, so the same issuer can have several over time.
     * @param issid issuer the key belongs to
     * @param counter which version of that issuer's key to grab
     * @returns the matching public key
     */
    public PublicKey(issid: IssuerIdentifier, counter: number): gabikeys.PublicKey {
        const pk: gabikeys.PublicKey | undefined = this.Conf?.publicKeys?.[issid]![counter]
        if (pk === undefined) {
            throw new Error(`Unknown public key: ${issid} - ${counter}`)
        }
        // not every key is generated with the extra parameters revocation needs,
        // so bail out early if this one wasn't
        if (!pk.revocationSupported()) {
            throw new Error("public key does not support revocation")
        }

        return pk
    }
}

/**
 * revocation settings for a single credential type.
 */
type RevocationSetting = {
    Server: boolean
    Authority: boolean
    RevocationServerURL: string
    Tolerance: number
    SSE: boolean

    updated: Date // when these settings were last refreshed
}

/**
 * maps each credential type to its revocation settings.
 */
export type RevocationSettings = Record<CredentialTypeIdentifier, RevocationSetting>
