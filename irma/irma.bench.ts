import { describe, expect } from "vitest"
import { Configuration } from "./irmaconfig"
import { AttributeType, CredentialType, SchemeManager } from "./descriptions"
import { parseSignedMessage } from "./verify"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"

// Hardcoded signed message used as the fixture every benchmark verifies.
const SIGNED_MESSAGES_JSON = [
    `{
      "signature":[{
        "c":"pliyrSE7wXcDcKXuBtZW5bnucvBSXpILIRvnNBgx7hQ=",
        "A":"D/8wLPq9860bpXZ5c+VYyoPJ+Z8CWDZNQ0jXvst8qnPRdivy/GQIfJHjVnpOPlHbguphb/7JVbfcV3bZeybA3bCF/4UesjRUZlMf/iJ/QgKHbt41ogN1PPT5z7qBJpkxuNTIkHxaUPoDvhouHmuC9pNj4afRUyLJerxKPkpdBw0=",
        "e_response":"YOrKTrMSs4/QOUtPkT0YaYNEmW7Cs+cu624zr2xrHodyL88ub6yaXB7MGHAcQ1+iXsGN8jkfxB/0",
        "v_response":"AYSa1p8ISs//MsocJjODwWuPB/z6+iKHHi+sTToRs0eJ2X1gwmWoA5QB0aHjRkWye3/+2rtosfUzI77FlPQVnrbMERwcuYM/fx3fpNCpjm2qcs3AOJRcSRxcNFMe1+4ECsmJhByMDutS1KXAAKiNvnhEXx9f0JrQGwQFtpSFPh8dOuvEKUZHAUALr4FcHCa2HL9nDRiqy2KAOxE0nAANAcMaBo/ed+WZeHtv4CTB7egyYs27cklVbwlBzmRrbjNZk57ICd0jVd6SZ2Ir93r/aPejkyhQ03xh9RVVyhOn4bkbjKIBzEybXTJAXgNmvd6F8Ds00srBZVWlo7Z23JZ7",
        "a_responses":{
          "0":"QHTznWWrECRNNmUNcy0yGu2L6qsZU6qkvaII8QB8QjbUxpwHzSeJWkzrn/Kk1KIowfoqB1DKGaFLATvuBl+bCoJjea+2VfK9Ns8=",
          "2":"H57Y9CTXJ5MAVo+aFfNSbmRMFQpraBIZVOXiRxCD/P7Aw4fW8r9P5l9pO9DTUeExaqFzsLyF5i5EridVWxlP2Wv0zbH8ku9Sg9w=",
          "3":"joggAmOhqM4QsKdoLHAfaslzXqJswS7MwZ/5+AKYdkMaHQ45biMdZU/6R+B7bjvsumg2f6KyTyg0G+BI+wVdJOjh3kGezdANB7Y=",
          "5":"5YP4A82WWeqc33e5Zg/Q8lqQQ1amLE8mOxMwCXb3N4J0UJRfV9lUFvbH1Q3Yb3YHAZpzGvhN/pBacwqktMkP4L71PnMldqA+nqA="
        },
        "a_disclosed":{
          "1":"AgAJuwB+AALWy2qU9p3l52l9LU1rVT4M",
          "4":"NDU2"
        }
      }],
      "nonce":"Kg==",
      "context":"BTk=",
      "message":"I owe you everything",
      "timestamp":{
        "Time":1527196489,
        "ServerUrl":"https://metrics.privacybydesign.foundation/atum",
        "Sig":{
          "Alg":"ed25519",
          "Data":"ZV1qkvDrFK14QrUSC66xTNr9HitCOV4vwfGX0bh3iwY7qyHCi9rIOE97KY8CZifU5oLgVhFWy5E+ALR+gEpACw==",
          "PublicKey":"e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8="
        }
      }
    }`,
]

// Host machine and toolchain details recorded with each report
interface MachineStats {
    platform: string
    arch: string
    cpuModel: string
    cpuCores: number
    totalMemory: string
    freeMemory: string
    nodeVersion: string
    viteVersion: string
    vitestVersion: string
    timestamp: string
}

// Timings and summary statistics for one benchmark
interface BenchmarkResult {
    name: string
    iterations: number
    individualTimes: number[] // milliseconds
    mean: number
    median: number
    min: number
    max: number
    stdDev: number
    variance: number
}

// Computes mean, median, min, max, stddev and variance for a list of timings
function calculateStats(times: number[]): Omit<BenchmarkResult, "name" | "iterations"> {
    if (times.length === 0) {
        throw new Error("No times provided")
    }

    const sorted = [...times].sort((a, b) => a - b)
    const mean = times.reduce((a, b) => a + b, 0) / times.length
    const median =
        times.length % 2 === 0
            ? (sorted[times.length / 2 - 1]! + sorted[times.length / 2]!) / 2
            : sorted[Math.floor(times.length / 2)]!

    const variance = times.reduce((sum, time) => sum + Math.pow(time - mean, 2), 0) / times.length
    const stdDev = Math.sqrt(variance)

    return {
        individualTimes: times,
        mean,
        median,
        min: sorted[0]!,
        max: sorted[sorted.length - 1]!,
        stdDev,
        variance,
    }
}

// Reads host and toolchain details for the report
function getMachineStats(): MachineStats {
    const cpus = os.cpus()
    const packageJson = JSON.parse(
        fs.readFileSync(path.join(process.cwd(), "package.json"), "utf-8")
    )

    return {
        platform: os.platform(),
        arch: os.arch(),
        cpuModel: cpus[0]?.model || "Unknown",
        cpuCores: cpus.length,
        totalMemory: `${(os.totalmem() / 1024 ** 3).toFixed(2)} GB`,
        freeMemory: `${(os.freemem() / 1024 ** 3).toFixed(2)} GB`,
        nodeVersion: process.version,
        viteVersion: packageJson.dependencies.vite || packageJson.devDependencies.vite || "Unknown",
        vitestVersion: packageJson.devDependencies.vitest || "Unknown",
        timestamp: new Date().toISOString(),
    }
}

// Runs warmup then timed iterations of fn and returns its statistics
async function runBenchmark(
    name: string,
    fn: () => Promise<void>,
    iterations: number,
    warmupIterations: number = 5
): Promise<BenchmarkResult> {
    for (let i = 0; i < warmupIterations; i++) {
        await fn()
    }

    const times: number[] = []
    for (let i = 0; i < iterations; i++) {
        const start = performance.now()
        await fn()
        const end = performance.now()
        times.push(end - start)
    }

    const stats = calculateStats(times)
    return {
        name,
        iterations,
        ...stats,
    }
}

// Renders the machine stats and benchmark results into a printable report
function formatBenchmarkReport(results: BenchmarkResult[], machineStats: MachineStats): string {
    const lines: string[] = []

    lines.push(`Benchmark Results Report`)
    lines.push("=".repeat(80))
    lines.push(`Timestamp:              ${machineStats.timestamp}`)
    lines.push("")

    lines.push("MACHINE STATISTICS")
    lines.push("-".repeat(80))
    lines.push(`Platform:               ${machineStats.platform}`)
    lines.push(`Architecture:           ${machineStats.arch}`)
    lines.push(`CPU Model:              ${machineStats.cpuModel}`)
    lines.push(`CPU Cores:              ${machineStats.cpuCores}`)
    lines.push(`Total Memory:           ${machineStats.totalMemory}`)
    lines.push(`Free Memory:            ${machineStats.freeMemory}`)
    lines.push(`Node Version:           ${machineStats.nodeVersion}`)
    lines.push(`Vite Version:           ${machineStats.viteVersion}`)
    lines.push(`Vitest Version:         ${machineStats.vitestVersion}`)
    lines.push("")

    lines.push("BENCHMARK RESULTS")
    lines.push("=".repeat(80))
    lines.push("")

    for (const result of results) {
        lines.push(`Test: ${result.name}`)
        lines.push("-".repeat(80))
        lines.push(`  Iterations:           ${result.iterations}`)
        lines.push(`  Mean:                 ${result.mean.toFixed(3)} ms`)
        lines.push(`  Median:               ${result.median.toFixed(3)} ms`)
        lines.push(`  Min:                  ${result.min.toFixed(3)} ms`)
        lines.push(`  Max:                  ${result.max.toFixed(3)} ms`)
        lines.push(`  Std Dev:              ${result.stdDev.toFixed(3)} ms`)
        lines.push(`  Variance:             ${result.variance.toFixed(3)} ms²`)
        lines.push(`  Coefficient of Var:   ${((result.stdDev / result.mean) * 100).toFixed(2)}%`)
        lines.push("")

        const indexedTimes = result.individualTimes.map((time, index) => ({ time, index }))
        const sortedByTime = [...indexedTimes].sort((a, b) => a.time - b.time)

        const fastest = sortedByTime.slice(0, 10)
        const slowest = sortedByTime.slice(-10).reverse()

        lines.push(`  10 Fastest Runs:`)
        for (let i = 0; i < fastest.length; i++) {
            lines.push(
                `    [${i + 1}] Run #${fastest[i]!.index + 1}: ${fastest[i]!.time.toFixed(3)} ms`
            )
        }
        lines.push("")

        lines.push(`  10 Slowest Runs:`)
        for (let i = 0; i < slowest.length; i++) {
            lines.push(
                `    [${i + 1}] Run #${slowest[i]!.index + 1}: ${slowest[i]!.time.toFixed(3)} ms`
            )
        }
        lines.push("")
    }

    lines.push("SUMMARY TABLE")
    lines.push("=".repeat(80))
    lines.push(
        `${"Test Name".padEnd(40)} ${"Mean (ms)".padEnd(15)} ${"Std Dev".padEnd(12)} ${"Min".padEnd(12)} ${"Max".padEnd(12)}`
    )
    lines.push("-".repeat(80))
    for (const result of results) {
        const name = result.name.substring(0, 39).padEnd(40)
        const mean = result.mean.toFixed(3).padEnd(15)
        const stdDev = result.stdDev.toFixed(3).padEnd(12)
        const min = result.min.toFixed(3).padEnd(12)
        const max = result.max.toFixed(3).padEnd(12)
        lines.push(`${name} ${mean} ${stdDev} ${min} ${max}`)
    }
    lines.push("")

    return lines.join("\n")
}

// Writes the report to the next free test-results/test-N file and returns its path
function saveResults(results: BenchmarkResult[], machineStats: MachineStats): string {
    const resultsDir = path.join(process.cwd(), "test-results")

    if (!fs.existsSync(resultsDir)) {
        fs.mkdirSync(resultsDir, { recursive: true })
    }

    // Find the next available test number.
    let nextTestNumber = 0
    const files = fs.readdirSync(resultsDir)
    for (const file of files) {
        const match = file.match(/^test-(\d+)$/)
        if (match) {
            const num = parseInt(match[1]!, 10)
            nextTestNumber = Math.max(nextTestNumber, num + 1)
        }
    }

    const report = formatBenchmarkReport(results, machineStats)
    const filePath = path.join(resultsDir, `test-${nextTestNumber}`)
    fs.writeFileSync(filePath, report)

    console.log(`Results saved to ${filePath}`)
    console.log(report)

    return filePath
}

// Benchmarks verify() under several iteration and warmup configurations.
describe("Performance Tests", async () => {
    const irmaSignedMessageJson = SIGNED_MESSAGES_JSON[0]!
    const message = await parseSignedMessage(irmaSignedMessageJson)

    const conf: Configuration = new Configuration({
        schemeManagers: {
            "irma-demo": new SchemeManager({
                id: "irma-demo",
                demo: true,
                status: "Valid",
            }),
        },
        issuers: {
            "irma-demo.RU": {
                id: "RU",
                name: {
                    en: "Demo Radboud University Nijmegen",
                    nl: "Demo Radboud Universiteit Nijmegen",
                },
                schemeManagerID: "irma-demo",
                contactAddress: "",
                contactEMail: "",
                deprecatedSince: {
                    time: new Date(0),
                    serverURL: "",
                    sig: { alg: "", data: new Uint8Array(), publicKey: new Uint8Array() },
                },
                languages: ["en", "nl"],
                xmlVersion: 0,
            },
        },
        credentialTypes: {
            "irma-demo.RU.studentCard": new CredentialType({
                id: "studentCard",
                issuerID: "RU",
                schemeManagerID: "irma-demo",
                attributeTypes: [
                    new AttributeType({
                        id: "university",
                        credentialTypeID: "studentCard",
                        issuerID: "RU",
                        schemeManagerID: "irma-demo",
                    }),
                    new AttributeType({
                        id: "studentCardNumber",
                        credentialTypeID: "studentCard",
                        issuerID: "RU",
                        schemeManagerID: "irma-demo",
                    }),
                    new AttributeType({
                        id: "studentID",
                        credentialTypeID: "studentCard",
                        issuerID: "RU",
                        schemeManagerID: "irma-demo",
                    }),
                    new AttributeType({
                        id: "level",
                        credentialTypeID: "studentCard",
                        issuerID: "RU",
                        schemeManagerID: "irma-demo",
                    }),
                ],
            }),
        },
    })

    // Prefetch data once before benchmarking
    await conf.fetchPublicKeys("irma-demo.RU")
    await conf.reverseReverseHashes()

    // Collect machine statistics once
    const machineStats = getMachineStats()

    // Run all benchmarks and collect results
    const results: BenchmarkResult[] = []

    // Test 1: 1000 measurements of 1 verification, no warmup
    results.push(
        await runBenchmark(
            "1x1000 verifications, no warmup",
            async () => {
                await message.verify(conf)
            },
            1000,
            0
        )
    )

    // Test 2: 1000 measurements of 1 verification, with warmup (5 iterations)
    results.push(
        await runBenchmark(
            "1x1000 verifications, with warmup",
            async () => {
                await message.verify(conf)
            },
            1000,
            5
        )
    )

    // Test 3: 10000 measurements of 1 verification, no warmup
    results.push(
        await runBenchmark(
            "1x10000 verifications, no warmup",
            async () => {
                await message.verify(conf)
            },
            10000,
            0
        )
    )

    // Test 4: 10000 measurements of 1 verification, with warmup (10 iterations)
    results.push(
        await runBenchmark(
            "1x10000 verifications, with warmup",
            async () => {
                await message.verify(conf)
            },
            10000,
            10
        )
    )

    // Test 5: 100 measurements of 100 verifications, no warmup
    results.push(
        await runBenchmark(
            "100x100 verifications, no warmup",
            async () => {
                for (let i = 0; i < 100; i++) {
                    await message.verify(conf)
                }
            },
            100,
            0
        )
    )

    // Test 6: 100 measurements of 100 verifications, with warmup
    results.push(
        await runBenchmark(
            "100x100 verifications, with warmup",
            async () => {
                for (let i = 0; i < 100; i++) {
                    await message.verify(conf)
                }
            },
            100,
            5
        )
    )

    // Test 7: 100 measurements of 1000 verifications, no warmup
    results.push(
        await runBenchmark(
            "100x1000 verifications, no warmup",
            async () => {
                for (let i = 0; i < 1000; i++) {
                    await message.verify(conf)
                }
            },
            100,
            0
        )
    )

    // Test 8: 100 measurements of 1000 verifications, with warmup
    results.push(
        await runBenchmark(
            "100x1000 verifications, with warmup",
            async () => {
                for (let i = 0; i < 1000; i++) {
                    await message.verify(conf)
                }
            },
            100,
            5
        )
    )

    // Save all results to a single file
    console.log("\n" + "=".repeat(80))
    console.log("FINAL BENCHMARK REPORT")
    console.log("=".repeat(80))
    saveResults(results, machineStats)

    expect(true).toBe(true)
})
