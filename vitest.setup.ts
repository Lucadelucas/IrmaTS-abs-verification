import { webcrypto } from "crypto"

Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
})
