/**
 * small collection of modular arithmetic helpers built on native bigint.
 * everything here works with arbitrary precision so the big crypto-sized
 * numbers don't overflow like they would with regular number.
 */
export namespace BigIntTool {
    /**
     * extended euclidean algorithm. besides the gcd it also gives the
     * bezout coefficients x and y, which is what lets us derive a modular
     * inverse later on.
     *
     * @param a first value
     * @param b second value
     * @returns [gcd, x, y] satisfying ax + by = gcd(a, b)
     */
    function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
        let old_r = a,
            r = b
        let old_s = 1n,
            s = 0n
        let old_t = 0n,
            t = 1n

        while (r !== 0n) {
            const quotient = old_r / r
            const temp_r = r
            r = old_r - quotient * r
            old_r = temp_r

            const temp_s = s
            s = old_s - quotient * s
            old_s = temp_s

            const temp_t = t
            t = old_t - quotient * t
            old_t = temp_t
        }

        return [old_r, old_s, old_t]
    }

    /**
     * modular inverse of n mod modulus. an inverse only exists when n and
     * modulus are coprime, so if the gcd isn't 1 we throw instead of
     * returning something bogus.
     *
     * @param n value to invert
     * @param modulus the modulus
     * @returns the inverse in the range [0, modulus)
     */
    export function modInv(n: bigint | number, modulus: bigint | number): bigint {
        if (typeof n === "number") n = BigInt(n)
        if (typeof modulus === "number") modulus = BigInt(modulus)

        const [gcd, x] = egcd(n, modulus)

        if (gcd !== 1n) {
            throw new Error(`No modular inverse for ${n} mod ${modulus} since gcd is ${gcd}`)
        }

        // x can come back negative, so wrap it back into [0, modulus)
        return ((x % modulus) + modulus) % modulus
    }

    /**
     * computes (base^exponent) mod modulus using square-and-multiply, so it
     * stays fast even for huge exponents instead of multiplying one at a time.
     *
     * **NOTE** a negative exponent just skips the loop and returns 1n, it does not
     * try to take an inverse.
     *
     * @param base the base
     * @param exponent the exponent
     * @param modulus the modulus
     * @returns base raised to exponent, reduced mod modulus
     */
    export function modExp(
        base: bigint | number,
        exponent: bigint | number,
        modulus: bigint | number
    ): bigint {
        base = typeof base === "number" ? BigInt(base) : base
        exponent = typeof exponent === "number" ? BigInt(exponent) : exponent
        modulus = typeof modulus === "number" ? BigInt(modulus) : modulus

        if (modulus === 1n) return 0n

        let result = 1n
        base %= modulus

        while (exponent > 0n) {
            // multiply in base when the current low bit is set
            if (exponent % 2n === 1n) {
                result = (result * base) % modulus
            }
            exponent >>= 1n
            base = (base * base) % modulus
        }

        return result
    }

    /**
     * multiplies a whole list of values together mod modulus, reducing after
     * each step so the running product never blows up in size.
     *
     * @param bases values to multiply
     * @param modulus the modulus
     * @returns the product reduced mod modulus
     */
    export function modMult(bases: (bigint | number)[], modulus: bigint | number): bigint {
        modulus = typeof modulus === "number" ? BigInt(modulus) : modulus

        let result = 1n

        for (const b of bases) {
            const base: bigint = typeof b === "number" ? BigInt(b) : b
            result = (result * base) % modulus
        }

        return result
    }

    /**
     * number of bits needed to represent n. we just look at the length of its
     * binary string, which is good enough for the sizes we deal with here.
     *
     * @param n value to measure
     * @returns the bit length
     */
    export function bitLength(n: bigint | number): number {
        n = typeof n === "number" ? BigInt(n) : n
        return n.toString(2).length
    }
}
