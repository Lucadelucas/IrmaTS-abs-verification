import * as gabikeys from "../gabi/gabikeys/keys.ts"
import { IssuerIdentifier } from "./identifiers.ts"

export interface PrivateKeyRing {

    latest(id: IssuerIdentifier): gabikeys.PrivateKey

    get(id: IssuerIdentifier, counter: number): gabikeys.PrivateKey

    iterate(id: IssuerIdentifier, f: (sk: gabikeys.PrivateKey) => void): void
}

/**
 * combines several key rings into a single one, so lookups can fall through
 * multiple sources as if they were one ring
 */
export class PrivateKeyRingMerge implements PrivateKeyRing {
    rings?: PrivateKeyRing[]

    constructor(rings?: PrivateKeyRing[]) {
        this.rings = rings
    }

    get(_id: IssuerIdentifier, _counter: number): gabikeys.PrivateKey {
        throw new Error("Not implemented")
    }

    iterate(_id: IssuerIdentifier, _f: (sk: gabikeys.PrivateKey) => void): void {
        throw new Error("Not implemented")
    }

    latest(_id: IssuerIdentifier): gabikeys.PrivateKey {
        throw new Error("Not implemented")
    }

    add(_ring: PrivateKeyRing): void {
        throw new Error("Not implemented")
    }
}
