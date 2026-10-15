package irma

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// BenchmarkResult holds the statistics for a single benchmark test
type BenchmarkResult struct {
	Name             string
	Iterations       int
	IndividualTimes  []float64 // milliseconds
	Mean             float64
	Median           float64
	Min              float64
	Max              float64
	StdDev           float64
	Variance         float64
}

// MachineStats holds information about the machine running the benchmark
type MachineStats struct {
	Platform    string
	Arch        string
	NumCPU      int
	GoVersion   string
	Timestamp   string
}

func calculateStats(times []float64) BenchmarkResult {
	if len(times) == 0 {
		return BenchmarkResult{}
	}

	// Calculate mean
	sum := 0.0
	for _, t := range times {
		sum += t
	}
	mean := sum / float64(len(times))

	// Calculate median
	sorted := make([]float64, len(times))
	copy(sorted, times)
	sort.Float64s(sorted)

	var median float64
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	} else {
		median = sorted[len(sorted)/2]
	}

	// Calculate variance and std dev
	variance := 0.0
	for _, t := range times {
		variance += math.Pow(t-mean, 2)
	}
	variance /= float64(len(times))
	stdDev := math.Sqrt(variance)

	return BenchmarkResult{
		IndividualTimes: times,
		Mean:            mean,
		Median:          median,
		Min:             sorted[0],
		Max:             sorted[len(sorted)-1],
		StdDev:          stdDev,
		Variance:        variance,
	}
}

func getMachineStats() MachineStats {
	return MachineStats{
		Platform:  runtime.GOOS,
		Arch:      runtime.GOARCH,
		NumCPU:    runtime.NumCPU(),
		GoVersion: runtime.Version(),
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

func runBenchmark(name string, fn func() error, numMeasurements int, warmupIterations int) (BenchmarkResult, error) {
	// Warmup iterations
	for i := 0; i < warmupIterations; i++ {
		if err := fn(); err != nil {
			return BenchmarkResult{}, err
		}
	}

	// Actual benchmark measurements
	times := make([]float64, numMeasurements)
	for i := 0; i < numMeasurements; i++ {
		start := time.Now()
		if err := fn(); err != nil {
			return BenchmarkResult{}, err
		}
		end := time.Now()
		times[i] = end.Sub(start).Seconds() * 1000 // convert to milliseconds
	}

	result := calculateStats(times)
	result.Name = name
	result.Iterations = numMeasurements
	return result, nil
}

func formatBenchmarkReport(results []BenchmarkResult, machineStats MachineStats) string {
	var sb strings.Builder

	// Header
	sb.WriteString("Benchmark Results Report\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString(fmt.Sprintf("Timestamp:              %s\n", machineStats.Timestamp))
	sb.WriteString("\n")

	// Machine Statistics Section
	sb.WriteString("MACHINE STATISTICS\n")
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	sb.WriteString(fmt.Sprintf("Platform:               %s\n", machineStats.Platform))
	sb.WriteString(fmt.Sprintf("Architecture:           %s\n", machineStats.Arch))
	sb.WriteString(fmt.Sprintf("CPU Cores:              %d\n", machineStats.NumCPU))
	sb.WriteString(fmt.Sprintf("Go Version:             %s\n", machineStats.GoVersion))
	sb.WriteString("\n")

	// Benchmark Results Section
	sb.WriteString("BENCHMARK RESULTS\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString("\n")

	for _, result := range results {
		sb.WriteString(fmt.Sprintf("Test: %s\n", result.Name))
		sb.WriteString(strings.Repeat("-", 80) + "\n")
		sb.WriteString(fmt.Sprintf("  Iterations:           %d\n", result.Iterations))
		sb.WriteString(fmt.Sprintf("  Mean:                 %.3f ms\n", result.Mean))
		sb.WriteString(fmt.Sprintf("  Median:               %.3f ms\n", result.Median))
		sb.WriteString(fmt.Sprintf("  Min:                  %.3f ms\n", result.Min))
		sb.WriteString(fmt.Sprintf("  Max:                  %.3f ms\n", result.Max))
		sb.WriteString(fmt.Sprintf("  Std Dev:              %.3f ms\n", result.StdDev))
		sb.WriteString(fmt.Sprintf("  Variance:             %.3f ms²\n", result.Variance))
		sb.WriteString(fmt.Sprintf("  Coefficient of Var:   %.2f%%\n", (result.StdDev/result.Mean)*100))
		sb.WriteString("\n")

		// Sort times to find fastest and slowest
		type timeWithIndex struct {
			time  float64
			index int
		}
		indexedTimes := make([]timeWithIndex, len(result.IndividualTimes))
		for i, t := range result.IndividualTimes {
			indexedTimes[i] = timeWithIndex{time: t, index: i}
		}

		sort.Slice(indexedTimes, func(i, j int) bool {
			return indexedTimes[i].time < indexedTimes[j].time
		})

		fastest := indexedTimes
		if len(fastest) > 10 {
			fastest = fastest[:10]
		}

		sb.WriteString("  10 Fastest Runs:\n")
		for i, t := range fastest {
			sb.WriteString(fmt.Sprintf("    %d. Run %d: %.3f ms\n", i+1, t.index, t.time))
		}
		sb.WriteString("\n")

		slowest := indexedTimes
		if len(slowest) > 10 {
			slowest = slowest[len(slowest)-10:]
		}
		sort.Slice(slowest, func(i, j int) bool {
			return slowest[i].time > slowest[j].time
		})

		sb.WriteString("  10 Slowest Runs:\n")
		for i, t := range slowest {
			sb.WriteString(fmt.Sprintf("    %d. Run %d: %.3f ms\n", i+1, t.index, t.time))
		}
		sb.WriteString("\n")
	}

	// Summary table
	sb.WriteString("SUMMARY TABLE\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString(fmt.Sprintf("%-40s %-15s %-12s %-12s %-12s\n", "Test Name", "Mean (ms)", "Std Dev", "Min", "Max"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	for _, result := range results {
		name := result.Name
		if len(name) > 39 {
			name = name[:39]
		}
		sb.WriteString(fmt.Sprintf("%-40s %-15.3f %-12.3f %-12.3f %-12.3f\n",
			name, result.Mean, result.StdDev, result.Min, result.Max))
	}
	sb.WriteString("\n")

	return sb.String()
}

func saveResults(results []BenchmarkResult, machineStats MachineStats) (string, error) {
	resultsDir := "test-results"

	// Create directory if it doesn't exist
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return "", err
	}

	// Find the next available test number
	files, err := os.ReadDir(resultsDir)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}

	nextTestNumber := 0
	for _, file := range files {
		if !file.IsDir() {
			var num int
			_, err := fmt.Sscanf(file.Name(), "test-%d", &num)
			if err == nil && num >= nextTestNumber {
				nextTestNumber = num + 1
			}
		}
	}

	report := formatBenchmarkReport(results, machineStats)
	filePath := filepath.Join(resultsDir, fmt.Sprintf("test-%d", nextTestNumber))

	if err := os.WriteFile(filePath, []byte(report), 0644); err != nil {
		return "", err
	}

	return filePath, nil
}

func getVerifyBenchmarkData(b *testing.B) (*Configuration, *SignedMessage) {
	conf, err := NewConfiguration("testdata/irma_configuration", ConfigurationOptions{})
	if err != nil {
		b.Fatalf("Failed to create configuration: %v", err)
	}
	if err := conf.ParseFolder(); err != nil {
		b.Fatalf("Failed to parse configuration: %v", err)
	}

	irmaSignedMessageJson := `{"signature":[{"c":"pliyrSE7wXcDcKXuBtZW5bnucvBSXpILIRvnNBgx7hQ=","A":"D/8wLPq9860bpXZ5c+VYyoPJ+Z8CWDZNQ0jXvst8qnPRdivy/GQIfJHjVnpOPlHbguphb/7JVbfcV3bZeybA3bCF/4UesjRUZlMf/iJ/QgKHbt41ogN1PPT5z7qBJpkxuNTIkHxaUPoDvhouHmuC9pNj4afRUyLJerxKPkpdBw0=","e_response":"YOrKTrMSs4/QOUtPkT0YaYNEmW7Cs+cu624zr2xrHodyL88ub6yaXB7MGHAcQ1+iXsGN8jkfxB/0","v_response":"AYSa1p8ISs//MsocJjODwWuPB/z6+iKHHi+sTToRs0eJ2X1gwmWoA5QB0aHjRkWye3/+2rtosfUzI77FlPQVnrbMERwcuYM/fx3fpNCpjm2qcs3AOJRcSRxcNFMe1+4ECsmJhByMDutS1KXAAKiNvnhEXx9f0JrQGwQFtpSFPh8dOuvEKUZHAUALr4FcHCa2HL9nDRiqy2KAOxE0nAANAcMaBo/ed+WZeHtv4CTB7egyYs27cklVbwlBzmRrbjNZk57ICd0jVd6SZ2Ir93r/aPejkyhQ03xh9RVVyhOn4bkbjKIBzEybXTJAXgNmvd6F8Ds00srBZVWlo7Z23JZ7","a_responses":{"0":"QHTznWWrECRNNmUNcy0yGu2L6qsZU6qkvaII8QB8QjbUxpwHzSeJWkzrn/Kk1KIowfoqB1DKGaFLATvuBl+bCoJjea+2VfK9Ns8=","2":"H57Y9CTXJ5MAVo+aFfNSbmRMFQpraBIZVOXiRxCD/P7Aw4fW8r9P5l9pO9DTUeExaqFzsLyF5i5EridVWxlP2Wv0zbH8ku9Sg9w=","3":"joggAmOhqM4QsKdoLHAfaslzXqJswS7MwZ/5+AKYdkMaHQ45biMdZU/6R+B7bjvsumg2f6KyTyg0G+BI+wVdJOjh3kGezdANB7Y=","5":"5YP4A82WWeqc33e5Zg/Q8lqQQ1amLE8mOxMwCXb3N4J0UJRfV9lUFvbH1Q3Yb3YHAZpzGvhN/pBacwqktMkP4L71PnMldqA+nqA="},"a_disclosed":{"1":"AgAJuwB+AALWy2qU9p3l52l9LU1rVT4M","4":"NDU2"}}],"nonce":"Kg==","context":"BTk=","message":"I owe you everything","timestamp":{"Time":1527196489,"ServerUrl":"https://metrics.privacybydesign.foundation/atum","Sig":{"Alg":"ed25519","Data":"ZV1qkvDrFK14QrUSC66xTNr9HitCOV4vwfGX0bh3iwY7qyHCi9rIOE97KY8CZifU5oLgVhFWy5E+ALR+gEpACw==","PublicKey":"e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8="}}}`

	irmaSignedMessage := &SignedMessage{}
	if err := json.Unmarshal([]byte(irmaSignedMessageJson), irmaSignedMessage); err != nil {
		b.Fatalf("Failed to unmarshal signed message: %v", err)
	}

	return conf, irmaSignedMessage
}

func BenchmarkVerifyScenarios(b *testing.B) {
	conf, irmaSignedMessage := getVerifyBenchmarkData(b)

	scenarios := []struct {
		name         string
		batchSize    int
		measurements int
		warmup       int
	}{
		{"1x1000 verifications, no warmup", 1, 1000, 0},
		{"1x1000 verifications, with warmup", 1, 1000, 5},
		{"1x10000 verifications, no warmup", 1, 10000, 0},
		{"1x10000 verifications, with warmup", 1, 10000, 10},
		{"100x100 verifications, no warmup", 100, 100, 0},
		{"100x100 verifications, with warmup", 100, 100, 5},
		{"1000x100 verifications, no warmup", 1000, 100, 0},
		{"1000x100 verifications, with warmup", 1000, 100, 5},
	}

	machineStats := getMachineStats()
	results := make([]BenchmarkResult, 0, len(scenarios))

	for _, s := range scenarios {
		scenario := s // capture loop variable
		result, err := runBenchmark(
			scenario.name,
			func() error {
				for k := 0; k < scenario.batchSize; k++ {
					_, _, err := irmaSignedMessage.Verify(conf, nil)
					if err != nil {
						return err
					}
				}
				return nil
			},
			scenario.measurements,
			scenario.warmup,
		)

		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}

		results = append(results, result)
	}

	filePath, err := saveResults(results, machineStats)
	if err != nil {
		b.Fatalf("Failed to save results: %v", err)
	}

	report := formatBenchmarkReport(results, machineStats)
	fmt.Printf("\n%s\n", strings.Repeat("=", 80))
	fmt.Println("FINAL BENCHMARK REPORT")
	fmt.Printf("%s\n", strings.Repeat("=", 80))
	fmt.Println(report)
	fmt.Printf("Results saved to %s\n", filePath)
}
