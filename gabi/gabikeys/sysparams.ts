/**
 * the complete set of system parameters: the base bit lengths plus
 * everything derived from them. this is what the rest of the crypto
 * code actually reads from
 */
export interface SystemParameters extends BaseParameters, DerivedParameters {}

/**
 * the base bit lengths that every other length is computed from.
 * pick these per key size and the derived ones fall out
 */
interface BaseParameters {
    lePrime: number // bit length of the prime part of e
    lh: number // hash output length
    lm: number // attribute (message) length
    ln: number // RSA modulus length, i.e. the key size
    lstatzk: number // statistical zero-knowledge security parameter
}

/**
 * the lengths computed from the base params. these are all just
 * sums of the base lengths, see makeDerivedParameters for the formulas
 */
interface DerivedParameters {
    le: number // bit length of e
    leCommit: number // commitment length for e
    lmCommit: number // commitment length for an attribute
    lra: number // randomizer length
    lsCommit: number // commitment length for the secret
    lv: number // bit length of v
    lvCommit: number // commitment length for v
    lvPrime: number // bit length of v'
    lvPrimeCommit: number // commitment length for v'
}

// base params keyed by RSA modulus bit length (1024/2048/4096)
// note lstatzk and lm get bumped up for the larger key sizes
const defaultBaseParameters = {
    1024: {
        lePrime: 120,
        lh: 256,
        lm: 256,
        ln: 1024,
        lstatzk: 80,
    },
    2048: {
        lePrime: 120,
        lh: 256,
        lm: 256,
        ln: 2048,
        lstatzk: 128,
    },
    4096: {
        lePrime: 120,
        lh: 256,
        lm: 512,
        ln: 4096,
        lstatzk: 128,
    },
} satisfies Record<number, BaseParameters>

/**
 * works out the derived lengths from a set of base params.
 * each result is just a sum of base lengths with a small constant
 * @param base the base bit lengths to derive from
 * @returns the matching set of derived lengths
 */
function makeDerivedParameters(base: BaseParameters): DerivedParameters {
    const { ln, lstatzk, lh, lm, lePrime } = base
    // lv shows up in both lv and lvCommit so compute it once and reuse
    const Lv = ln + 2 * lstatzk + lh + lm + 4

    return {
        lra: ln + lstatzk,
        le: lstatzk + lh + lm + 5,
        leCommit: lePrime + lstatzk + lh,
        lmCommit: lm + lstatzk + lh,
        lsCommit: lm + lstatzk + lh + 1,
        lv: Lv,
        lvCommit: Lv + lstatzk + lh,
        lvPrime: ln + lstatzk,
        lvPrimeCommit: ln + 2 * lstatzk + lh,
    }
}

// the ready-to-use params per key length, base merged with its derived values
// look up by key size and you get the full SystemParameters object
export const DEFAULT_SYSTEM_PARAMETERS: Record<number, SystemParameters> = {
    1024: { ...defaultBaseParameters[1024], ...makeDerivedParameters(defaultBaseParameters[1024]) },
    2048: { ...defaultBaseParameters[2048], ...makeDerivedParameters(defaultBaseParameters[2048]) },
    4096: { ...defaultBaseParameters[4096], ...makeDerivedParameters(defaultBaseParameters[4096]) },
}

// the key lengths we have params for, in ascending order
// object keys come back as strings so map them back to numbers
export const defaultKeyLengths: number[] = Object.keys(DEFAULT_SYSTEM_PARAMETERS).map(Number)
