# IrmaTS

A TypeScript port of the Yivi (formerly IRMA) attribute-based signature verification path, based on the Go libraries [`gabi`](https://github.com/privacybydesign/gabi) and [`irmago`](https://github.com/privacybydesign/irmago).

It lets you verify a Yivi attribute-based signature **client-side or in your own backend, without an external IRMA/Yivi server**. You hand it a session result, and it returns the disclosed attributes together with a cryptographically established proof status.

## Features

- Verifies Yivi/IRMA attribute-based signatures (both v1 and v2 signature formats)
- No verifier server required: all checks run locally in TypeScript
- Auto-configuration: downloads the credential types and issuer public keys needed for a given session result
- Fails closed: the library never returns a partial success. Errors during cryptographic verification yield an `INVALID` result; malformed session results and auto-configuration failures reject with an error instead
- Does not trust the server's own `status`, `proofStatus` or `disclosed` fields; validity is derived from the signature itself
- Ships ESM and CommonJS builds with type declarations, tree-shakeable (`sideEffects: false`), built for the browser platform

## Installation

The package is not published to a registry. Build it from source:

```bash
git clone https://github.com/Lucadelucas/IrmaTS-abs-verification.git
cd IrmaTS-abs-verification
npm install
npm run build
```

The build output lands in `dist/`. You can then consume it locally, for example with `npm pack` or `npm link`.

## Usage

```ts
import { verifySignature, PROOF_STATUS_VALID } from "irmats"

// The full session result JSON of a signature session
// (what an IRMA server returns from GET /session/{token}/result).
const sessionResult = await fetch("/path/to/session-result.json").then((r) => r.json())

const { attributes, status } = await verifySignature(sessionResult)

if (status === PROOF_STATUS_VALID) {
    // attributes is a list of conjunctions, each a list of disclosed attributes
    for (const conjunction of attributes!) {
        for (const attribute of conjunction) {
            // rawValue is optional; fall back to the translated value if absent
            console.log(attribute.identifier, attribute.rawValue ?? attribute.value)
        }
    }
} else {
    console.warn(`Signature rejected: ${status}`)
}
```

`verifySignature` accepts the session result either as a parsed object or as a JSON string.

## API

### `verifySignature(response, configuration?)`

| Parameter       | Type                          | Description                                                                                                                          |
| --------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `response`      | `string \| SessionResultJSON` | The full IRMA session result containing the inner `signature` object.                                                                |
| `configuration` | `Configuration` (optional)    | A preloaded configuration to reuse. When omitted, one is downloaded based on the credential types named in the disclosed attributes. |

Returns `Promise<VerificationResult>`:

```ts
type VerificationResult = {
    attributes: DisclosedAttribute[][] | undefined // undefined when invalid
    status: ProofStatus
}
```

The disclosed ids in the session result only decide what gets downloaded. Correctness is still enforced cryptographically, because the credential's metadata hash is bound into the signature, so a mismatched credential simply fails verification.

**Rejections.** `verifySignature` can reject (throw) in two situations:

- the session result has no disclosed attributes, so auto-configuration cannot determine which credential types to load, or a network error occurs while fetching the configuration;
- the session result is malformed (e.g. the JSON is invalid or the inner `signature` object is missing).

Errors raised while parsing or verifying the signature itself are caught and mapped to `INVALID`. If you need a single catch-all outcome, wrap the call and treat any rejection as `INVALID` too.

### Proof statuses

| Constant               | Value       | Meaning                                                   |
| ---------------------- | ----------- | --------------------------------------------------------- |
| `PROOF_STATUS_VALID`   | `"VALID"`   | The signature verified and all credentials are unexpired. |
| `PROOF_STATUS_INVALID` | `"INVALID"` | The signature is malformed or does not verify.            |
| `PROOF_STATUS_EXPIRED` | `"EXPIRED"` | The signature verified, but a credential has expired.     |

Credential expiry is evaluated against the attached timestamp's time (or the current time if there is none).

### Exported types

`VerificationResult`, `ProofStatus`, `DisclosedAttribute`, `SessionResultJSON`

> **Note:** the `Configuration` class used by the `configuration` parameter is not exported from the package entry point. A preloaded configuration can therefore only be supplied when importing directly from the source (e.g. in tests or in-repo consumers); consumers of the built package always use auto-configuration.

## Security notes

> **Warning:** This library currently does **not** verify the signature of the fetched scheme, nor the Atum timestamp signature. Do not rely on it as the sole trust anchor in a production setting until those checks are in place.

Auto-configuration performs network requests to fetch credential type descriptions and issuer public keys. To avoid these requests you would need to pass a preloaded configuration, which currently requires importing from the source (see the note under API).

## Project structure

```
.
├── index.ts          Public entry point (re-exports the API)
├── irma/             irmago port: session results, signed messages, attributes, configuration
├── gabi/             gabi port: proofs, proof lists, issuer keys, hashing primitives
├── tsup.config.ts    Build configuration (ESM + CJS + .d.ts)
├── vitest.config.ts  Test configuration (jsdom, v8 coverage)
└── vitest.setup.ts   Test setup
```

## Development

| Command                | Description                          |
| ---------------------- | ------------------------------------ |
| `npm run build`        | Build ESM, CJS and type declarations |
| `npm test`             | Run tests in watch mode              |
| `npm run test:run`     | Run tests once                       |
| `npm run test:ui`      | Run tests with the Vitest UI         |
| `npm run coverage`     | Run tests with coverage (v8)         |
| `npm run bench`        | Run benchmarks                       |
| `npm run typecheck`    | Type-check without emitting          |
| `npm run lint`         | Lint with ESLint                     |
| `npm run lint:fix`     | Lint and auto-fix                    |
| `npm run format`       | Format with Prettier                 |
| `npm run format:check` | Check formatting                     |

Dependencies are intentionally small: [`asn1js`](https://github.com/PeculiarVentures/asn1.js) and [`fast-xml-parser`](https://github.com/NaturalIntelligence/fast-xml-parser).

## License

The original contributions of this project are licensed under the ISC license.

This project is a port of, and derives from, two upstream projects by the Privacy by Design Foundation:

- [`irmago`](https://github.com/privacybydesign/irmago), licensed under the Apache License 2.0
- [`gabi`](https://github.com/privacybydesign/gabi), licensed under the BSD 3-Clause License

The full license texts are in [`LICENSES.md`](LICENSES.md) and must be kept with any redistribution of this project.

## Acknowledgements

This project is a port of work by the [Yivi](https://yivi.app) team and the [Privacy by Design Foundation](https://privacybydesign.foundation), in particular `irmago` and `gabi`.
