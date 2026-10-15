import * as asn1 from "asn1js"

/**
 * hashes a list of bigints by DER-encoding them as [true, length, ...values]
 * and taking the sha-256 of that encoding, returned as a bigint.
 *
 * the element order and the sign-bit padding have to be exactly right,
 * otherwise the resulting hash won't match and verification fails.
 *
 * @param values the bigints to commit to, in order
 * @returns the sha-256 of the der encoding as a bigint
 */
export async function hashCommit(values: bigint[]): Promise<bigint> {
    const sequence = new asn1.Sequence()

    // leading boolean, always true
    sequence.valueBlock.value.push(new asn1.Boolean({ value: true }))

    // how many values follow
    sequence.valueBlock.value.push(new asn1.Integer({ value: values.length }))

    for (const val of values) {
        const hex = Encoding.bigIntToAsn1Hex(val)
        const buffer = Encoding.hexToBuffer(hex)
        sequence.valueBlock.value.push(new asn1.Integer({ valueHex: buffer }))
    }

    const der = sequence.toBER(false)
    return await Sha256.bufferToBigInt(der)
}

/**
 * conversion helpers between bigint and the various byte/string formats we need
 * (hex, raw bytes, base62, base64 and utf-8 strings)
 */
export namespace Encoding {
    const ALPH = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    /**
     * turns a non-negative bigint into hex with asn.1 sign-bit padding.
     * negatives aren't supported here, the sign is just dropped.
     *
     * @param val the bigint to encode
     * @returns the padded hex string
     */
    export function bigIntToAsn1Hex(val: bigint): string {
        let hex = val.toString(16)

        // drop leading minus; negatives are not encoded
        if (hex[0] === "-") {
            hex = hex.slice(1)
        }

        // pad to whole bytes
        if (hex.length & 1) {
            hex = "0" + hex
        }

        // prepend "00" so a leading byte >= 0x80 is not read as negative
        if (parseInt(hex.slice(0, 2), 16) >= 128) {
            hex = "00" + hex
        }

        return hex
    }

    /**
     * decodes a hex string into a buffer, reading two hex chars per byte
     *
     * @param hex the hex string to decode
     * @returns the resulting arraybuffer
     */
    export function hexToBuffer(hex: string): ArrayBuffer {
        const bytes = new Uint8Array(hex.length >> 1)
        for (let i = 0; i < bytes.length; i++) {
            const subHex: string = hex.substring(i * 2, 2 * i + 2)
            bytes[i] = parseInt(subHex, 16)
        }
        return bytes.buffer
    }

    /**
     * reads big-endian bytes back into a bigint
     *
     * @param bytes the big-endian byte array
     * @returns the decoded bigint
     */
    export function bytesToBigInt(bytes: Uint8Array): bigint {
        let n = 0n
        for (const byte of bytes) {
            n = (n << 8n) | BigInt(byte)
        }
        return n
    }

    /**
     * encodes the magnitude of a bigint as big-endian bytes.
     * the sign is ignored, and zero gives back an empty array.
     *
     * @param value the bigint whose magnitude we want
     * @returns the big-endian bytes
     */
    export function bigIntToBytes(value: bigint): Uint8Array<ArrayBuffer> {
        const absoluteValue = value < 0n ? -value : value

        if (absoluteValue === 0n) {
            return new Uint8Array(0)
        }

        let hex = absoluteValue.toString(16)
        if (hex.length & 1) {
            hex = "0" + hex
        }

        const len = hex.length >> 1
        const bytes = new Uint8Array(len)
        for (let i = 0; i < len; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
        }
        return bytes
    }

    /**
     * encodes a bigint as a base62 string using the ALPH alphabet.
     * zero is a special case and just returns "0".
     *
     * @param n the bigint to encode
     * @returns the base62 representation
     */
    export function bigIntToBase62(n: bigint): string {
        if (n === 0n) {
            return "0"
        }

        let result = ""
        let num = n
        while (num > 0n) {
            result = ALPH[Number(num % 62n)] + result
            num = num / 62n
        }
        return result
    }

    /**
     * decodes a base64 string into raw bytes
     *
     * @param base64 the base64 input
     * @returns the decoded bytes
     */
    export function base64ToBytes(base64: string): Uint8Array {
        return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))
    }

    /**
     * decodes a base64 string and interprets the bytes as a big-endian bigint
     *
     * @param base64 the base64 input
     * @returns the decoded bigint
     */
    export function base64ToBigInt(base64: string): bigint {
        const bytes: Uint8Array = base64ToBytes(base64)
        return bytesToBigInt(bytes)
    }

    /**
     * treats a bigint as packed big-endian bytes and decodes them as utf-8 text.
     * zero maps to the empty string since there are no bytes to read.
     *
     * @param value the bigint holding the byte sequence
     * @returns the decoded string
     */
    export function bigIntToString(value: bigint): string {
        if (value === 0n) {
            return ""
        }

        const bytes: number[] = []
        let tmp = value

        // peel off the low byte each step, prepend to stay big-endian
        while (tmp > 0n) {
            bytes.unshift(Number(tmp & 0xffn))
            tmp >>= 8n
        }

        return new TextDecoder().decode(new Uint8Array(bytes))
    }
}

/**
 * thin sha-256 wrappers built on the web crypto api, with the digest
 * returned in whatever shape the caller needs
 */
export namespace Sha256 {
    import bytesToBigInt = Encoding.bytesToBigInt
    import bigIntToBytes = Encoding.bigIntToBytes

    /**
     * hashes a buffer and reads the digest back as a big-endian bigint
     *
     * @param buffer the bytes to hash
     * @returns the sha-256 digest as a bigint
     */
    export async function bufferToBigInt(buffer: ArrayBuffer): Promise<bigint> {
        const hash = await globalThis.crypto.subtle.digest("SHA-256", buffer)
        return bytesToBigInt(new Uint8Array(hash))
    }

    /**
     * hashes the raw big-endian bytes of a bigint and returns the digest as a bigint.
     *
     * @param input the bigint to hash
     * @returns the sha-256 digest as a bigint
     */
    export async function bigIntToBigInt(input: bigint): Promise<bigint> {
        const buffer = bigIntToBytes(input)
        const hash = await globalThis.crypto.subtle.digest("SHA-256", buffer)
        return bytesToBigInt(new Uint8Array(hash))
    }

    /**
     * hashes a utf-8 string and gives back the raw digest buffer
     *
     * @param input the string to hash
     * @returns the sha-256 digest as an arraybuffer
     */
    export async function stringToArray(input: string): Promise<ArrayBuffer> {
        const buffer: ArrayBuffer = new TextEncoder().encode(input).buffer
        return globalThis.crypto.subtle.digest("SHA-256", buffer)
    }
}
