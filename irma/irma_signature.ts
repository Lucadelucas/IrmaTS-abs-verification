import { DisclosedAttributeIndices } from "./messages.ts"
import { Disclosure, ProofList } from "./verify.ts"
import { SignatureRequest } from "./requests.ts"
import { Timestamp } from "./timestamp.ts"
import { Sha256, Encoding } from "../gabi/internal/common/hashtool.ts"

import * as asn1 from "asn1js"

/**
 * the @context value marking a v2 attribute-based signature,
 * an empty string means the legacy v1 format
 */
export const LDContextSignedMessage = "https://irma.app/ld/signature/v2"

/**
 * a message signed with a Yivi/IRMA attribute-based signature, holds everything
 * needed to later verify it against a signature request
 */
export class SignedMessage {
    ldContext: string // @context, empty for v1 and the v2 url for v2
    signature: ProofList // the actual zero-knowledge proofs over the disclosed attributes
    indices: DisclosedAttributeIndices // which attributes were disclosed, per credential
    nonce: bigint // nonce binding the signature to a specific request
    context: bigint // context binding the signature to a specific request
    message: string // the plaintext that was signed
    timestamp?: Timestamp // optional trusted timestamp proving when this was signed

    constructor({
        ldContext = "",
        signature = new ProofList([]),
        indices = [],
        nonce = 0n,
        context = 0n,
        message = "",
        timestamp,
    }: Partial<SignedMessage>) {
        this.ldContext = ldContext
        this.signature = signature
        this.indices = indices
        this.nonce = nonce
        this.context = context
        this.message = message
        this.timestamp = timestamp
    }

    /**
     * figure out the signature format version from the @context
     * @returns 2 for a v2 signature, 1 for the legacy empty-context format
     */
    protected version(): number {
        if (this.ldContext == "") {
            return 1
        }
        return 2
    }

    /**
     * derive the real nonce as sha256(asn1(serverNonce, sha256(message), timestampSig))
     * and store it in this.nonce. this is what actually gets signed, so the message
     * and timestamp end up bound into the nonce itself
     * @param nonce - base64-encoded server nonce from the requestor
     */
    public async setNonce(nonce: string): Promise<void> {
        const sequence = new asn1.Sequence()

        // first element: the server nonce as an ASN.1 INTEGER
        const nonceBigInt = Encoding.base64ToBigInt(nonce)
        if (nonceBigInt < 0n) {
            throw new Error(
                `Invalid encoded server nonce: ${nonceBigInt} (base64 string: ${nonce})`
            )
        }
        // DER sign-bit padding so a positive value is never read as negative
        const nonceHex = Encoding.bigIntToAsn1Hex(nonceBigInt)
        sequence.valueBlock.value.push(
            new asn1.Integer({
                valueHex: Encoding.hexToBuffer(nonceHex),
            })
        )

        // second element: SHA256(message) as an ASN.1 INTEGER
        const msgHashBuffer = await Sha256.stringToArray(this.message)
        const msgHashBigInt = Encoding.bytesToBigInt(new Uint8Array(msgHashBuffer))

        const paddedMsgHashHex = Encoding.bigIntToAsn1Hex(msgHashBigInt)
        const paddedMsgHashBuffer = Encoding.hexToBuffer(paddedMsgHashHex)
        const asn1Msg = new asn1.Integer({ valueHex: paddedMsgHashBuffer })
        sequence.valueBlock.value.push(asn1Msg)

        // optional third element: the timestamp signature bytes as an OCTET STRING
        const timestampData = this.timestamp?.sig?.data
        if (timestampData instanceof Uint8Array) {
            const tsBuffer = timestampData.buffer.slice(
                timestampData.byteOffset,
                timestampData.byteOffset + timestampData.byteLength
            ) as ArrayBuffer
            sequence.valueBlock.value.push(new asn1.OctetString({ valueHex: tsBuffer }))
        }

        // serialize the SEQUENCE to DER
        const der = sequence.toBER(false)

        this.nonce = await Sha256.bufferToBigInt(der)
    }

    /**
     * check that this message's context and nonce match the request, which is what
     * binds the signature to that specific request and stops it being replayed elsewhere
     * @param request - the signature request to check against
     * @returns true if both context and nonce match
     */
    protected matchesNonceAndContext(request: SignatureRequest): boolean {
        return this.context === request.getContext() && this.nonce === request.Nonce
    }

    /**
     * pair the proof list with the disclosed-attribute indices
     * @returns a Disclosure wrapping the signature and its indices
     */
    protected disclosure(): Disclosure {
        return new Disclosure(this.signature, this.indices)
    }
}
