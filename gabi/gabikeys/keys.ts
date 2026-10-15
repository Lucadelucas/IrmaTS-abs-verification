import { DEFAULT_SYSTEM_PARAMETERS, SystemParameters } from "./sysparams"
import { BigIntTool } from "../internal/common/mathutil.ts"

/**
 * namespace + local name of an xml root element
 * the keys are stored as xml so we keep track of which element they came from
 */
type xmlName = {
    name: string
    space: string
}

/**
 * issuer idemix public key
 * holds the modulus, generators and attribute bases needed to verify proofs.
 * the optional g/h/ecdsa fields are only present when the issuer supports revocation
 */
export class PublicKey {
    xmlName: xmlName
    counter: number
    expiryDate: number
    n: bigint // modulus n
    z: bigint // generator Z
    s: bigint // generator S
    g?: bigint // generator G (revocation)
    h?: bigint // generator H (revocation)
    r: Bases
    epochLength: EpochLength
    ecdsaString?: string

    ecdsa?: CryptoKey
    params: SystemParameters
    issuer: string

    /**
     * builds a public key from a partial object, filling in sensible defaults
     * params defaults to the system parameters matching the bit length of n, so
     * you usually only need to pass the actual key material
     * @param init partial public key fields, anything left out gets a default
     */
    constructor({
        xmlName = { name: "", space: "" },
        counter = 0,
        expiryDate = 0,
        n = 0n,
        z = 0n,
        s = 0n,
        g,
        h,
        r = [0n],
        epochLength = 0,
        ecdsaString,
        ecdsa,
        params = DEFAULT_SYSTEM_PARAMETERS[BigIntTool.bitLength(n)]!,
        issuer = "",
    }: Partial<PublicKey>) {
        this.xmlName = xmlName
        this.counter = counter
        this.expiryDate = expiryDate
        this.n = n
        this.z = z
        this.s = s
        this.g = g
        this.h = h
        this.r = r
        this.epochLength = epochLength
        this.ecdsaString = ecdsaString
        this.ecdsa = ecdsa
        this.params = params
        this.issuer = issuer
    }

    // TODO: parse ECDSA revocation key

    /**
     * whether the key carries revocation parameters
     * @returns true if this key supports revocation
     */
    public revocationSupported(): boolean {
        return this.g !== undefined && this.h !== undefined && this.ecdsaString !== undefined
    }
}

/**
 * issuer idemix private key
 * the secret counterpart to the public key, holds the prime factors of n.
 * we only need this type for completeness, verification never touches it
 */
export type PrivateKey = {
    XMLName: xmlName
    Counter: number
    ExpiryDate: number
    P: bigint
    Q: bigint
    PPrime: bigint
    QPrime: bigint
    ECDSAString: string

    N: bigint
    ECDSA: CryptoKey
    Order: bigint
}

/**
 * public key bases R, used as attribute generators
 * one base per attribute slot, indexed in the same order as the attributes
 */
type Bases = bigint[]

/**
 * epoch length in seconds attached to a public key
 */
type EpochLength = number
