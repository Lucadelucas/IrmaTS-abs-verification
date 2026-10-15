import { Configuration } from "./irmaconfig.ts"
import * as gabikeys from "../gabi/gabikeys/keys.ts"
import { CredentialType } from "./descriptions.ts"
import { Encoding } from "../gabi/internal/common/hashtool.ts"

const EXPIRY_FACTOR: number = 60 * 60 * 24 * 7 // one week in seconds = 604800
const METADATA_LENGTH: number = 1 + 3 + 2 + 2 + 16 // total metadata size in bytes = 24

/**
 * describes where one field sits inside the 24-byte metadata buffer
 * we use this so each getter can just slice out the bytes it cares about
 */
class metadataField {
    length: number
    offset: number

    /**
     * @param length how many bytes the field takes up
     * @param offset where the field starts in the buffer
     */
    constructor(length?: number, offset?: number) {
        this.length = length ?? 0
        this.offset = offset ?? 0
    }
}

// fixed layout of the 24-byte metadata buffer, each entry is (length, offset)
const VERSION_FIELD = new metadataField(1, 0)
const SIGNING_DATE_FIELD = new metadataField(3, 1)
const VALIDITY_FIELD = new metadataField(2, 4)
const KEY_COUNTER_FIELD = new metadataField(2, 6)
const CREDENTIAL_ID = new metadataField(16, 8)

/**
 * decode a random-blind attribute bigint into its base62 string
 * @param attr the attribute value
 * @returns the base62 encoded string
 */
export function decodeRandomBlind(attr: bigint): string {
    return Encoding.bigIntToBase62(attr)
}

/**
 * decode an attribute bigint into its string value
 * @param attr the raw attribute value
 * @param metadataVersion metadata version, controls how the value is interpreted
 * @returns decoded string, or undefined when a version 3+ attribute is absent
 */
export function decodeAttribute(attr: bigint, metadataVersion: number = 2): string | undefined {
    // version 3+ uses the low bit as an existence flag
    if (metadataVersion >= 3) {
        if ((attr & 1n) === 0n) {
            return undefined
        }
        // drop the existence bit to recover the value bits
        attr = attr >> 1n
    }

    return Encoding.bigIntToString(attr)
}

/**
 * the metadata attribute packed into a single bigint
 * it bundles the credential type, signing date, validity period, key counter
 * and public key, and the methods below unpack each piece on demand
 */
export class MetadataAttribute {
    int: bigint
    pk?: gabikeys.PublicKey
    conf: Configuration

    /**
     * @param int the packed metadata integer
     * @param pk the public key
     * @param conf configuration used for lookups
     */
    constructor({
        int = 0n,
        pk = undefined,
        conf = new Configuration({}),
    }: Partial<MetadataAttribute>) {
        this.int = int
        this.pk = pk
        this.conf = conf
    }

    /**
     * unpack the metadata bigint into a fixed 24-byte big-endian buffer
     * note that anything past 24 bytes of an oversized int just gets dropped
     * @returns the 24-byte buffer
     */
    private bytes(): Uint8Array {
        if (this.int === undefined) {
            throw new Error("Int is undefined")
        }

        const bytes = new Uint8Array(METADATA_LENGTH).fill(0)
        let value: bigint = this.int

        // fill from the least-significant byte upward
        for (let i = METADATA_LENGTH - 1; i >= 0; i--) {
            bytes[i] = Number(value & 0xffn)
            value >>= 8n
        }

        return bytes
    }

    /**
     * resolve and cache the public key this metadata was signed with
     * looks it up by issuer and key counter if we don't already have it
     * @returns the public key
     */
    public publicKey(): gabikeys.PublicKey {
        if (this.pk === undefined) {
            const id: string = this.credentialType().issuerIdentifier()
            this.pk = this.conf.publicKeys?.[id]?.[this.keyCounter()]
        }

        if (!this.pk) {
            throw new Error(
                `Public key not found for ${this.credentialType().id} counter ${this.keyCounter()}`
            )
        }

        return this.pk as gabikeys.PublicKey
    }

    /**
     * read the single metadata version byte
     * @returns the version number
     */
    public version(): number {
        const version = this.field(VERSION_FIELD).at(0)
        if (version === undefined) {
            throw new Error("Could not parse version field")
        }
        return version
    }

    /**
     * read the public key counter from the 2-byte key-counter field
     * the two bytes are combined big-endian into one number
     * @returns the key counter
     */
    public keyCounter(): number {
        const bytes: Uint8Array = this.field(KEY_COUNTER_FIELD)
        if (!bytes || bytes.length < 2) {
            throw new Error("Invalid KEY_COUNTER_FIELD length")
        }
        // >>> 0 to force an unsigned result
        return ((bytes[0]! << 8) | bytes[1]!) >>> 0
    }

    /**
     * decode the signing date from the signing-date field
     * the field stores a count of week-epochs, which we turn back into a real date
     * @returns the signing date
     */
    public signingDate(): Date {
        let bytes: Uint8Array = this.field(SIGNING_DATE_FIELD)
        if (!bytes || bytes.length < 1) {
            throw new Error("Invalid SIGNING_DATE_FIELD length")
        }
        // skip the unused leading byte
        bytes = bytes.subarray(1)

        if (!bytes || bytes.length < 2) {
            throw new Error("Invalid SIGNING_DATE_FIELD length after subarray")
        }
        // epoch count to seconds since the unix epoch (>>> 0 forces unsigned)
        let timestamp: number = (((bytes[0]! << 8) | bytes[1]!) >>> 0) * EXPIRY_FACTOR

        timestamp *= 1000 // Date wants milliseconds, not seconds
        return new Date(timestamp)
    }

    /**
     * read the validity duration, measured in epochs of EXPIRY_FACTOR seconds each
     * @returns the number of epochs the credential stays valid
     */
    private validityDuration(): number {
        const bytes: Uint8Array = this.field(VALIDITY_FIELD)
        if (!bytes || bytes.length < 2) {
            throw new Error("Invalid VALIDITY_FIELD length")
        }
        // >>> 0 to force an unsigned result
        return ((bytes[0]! << 8) | bytes[1]!) >>> 0
    }

    /**
     * figure out the credential type by hashing the credential-id field
     * and matching it against the configuration
     * @returns the matching credential type
     */
    public credentialType(): CredentialType {
        return this.conf.hashToCredentialType(this.field(CREDENTIAL_ID))
    }

    /**
     * compute the expiry date by pushing the signing date forward
     * by validityDuration epochs
     * @returns the expiry date
     */
    public expiry(): Date {
        const expiry: number =
            this.signingDate().getTime() + this.validityDuration() * EXPIRY_FACTOR * 1000
        return new Date(expiry)
    }

    /**
     * slice out the bytes belonging to one field of the metadata buffer
     * @param field the field layout (offset and length) to read
     * @returns the bytes for that field
     */
    private field(field: metadataField): Uint8Array {
        return this.bytes().subarray(field.offset, field.offset + field.length)
    }
}

/**
 * convenience helper to build a MetadataAttribute from its raw integer
 * @param i the packed metadata integer
 * @param conf configuration used for lookups
 * @returns the wrapped MetadataAttribute
 */
export function metadataFromInt(i: bigint, conf: Configuration): MetadataAttribute {
    return new MetadataAttribute({ int: i, conf: conf })
}
