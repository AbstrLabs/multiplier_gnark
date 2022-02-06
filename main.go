package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
	// "bytes"

    "github.com/fxamacker/cbor/v2"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

const N int = 200000

type Circuit struct {
	A frontend.Variable
	B frontend.Variable
// 	C frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	var V [N]frontend.Variable
	V[0] = api.Add(api.Mul(circuit.A, circuit.A), circuit.B)
	start := api.Tag("start")
	for i := 1; i < N; i++ {
		V[i] = api.Add(api.Mul(V[i-1], V[i-1]), circuit.B)
//         temp := api.Tag(string(i))
//         api.AddCounter(start, temp)
	}
// 	api.Println(V[N-1])
// 	api.AssertIsEqual(circuit.C, V[N-1])
	end := api.Tag("end")
    api.AddCounter(start, end)
	return nil
}

func setup(serialType string) {
	var circuit Circuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		panic("compile failed")
	}

	counters := r1cs.GetCounters()
	for _, c := range counters {
        fmt.Println(c)
    }

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic("setup failed")
	}

	writeToFile(serialType, r1cs, pk, vk)
}

func prove(r1cs frontend.CompiledConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) {
	var w Circuit
	w.A = 666
	w.B = 233
// 	N = 13000
// 	w.C = "6793544489128382459281307073994348887771341450407551491096489485513352038568"
// 	N = 13000000
// 	w.C = "11627185319010103288157029572521291604665626512789572484375095826433360489871"

    witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
    if err != nil {
        log.Fatal(err)
    }

    witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
    if err != nil {
        log.Fatal(err)
    }

	proof, err := groth16.Prove(r1cs, pk, witnessFull)
	if err != nil {
		panic("prove failed")
	}

	err = groth16.Verify(proof, vk, witnessPublic)
	if err != nil {
		panic("verification failed")
	}
	fmt.Println("prove succeeded")
}

func writeToFile(serialType string, r1cs frontend.CompiledConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) {
	// var buf bytes.Buffer
	f1, _ := os.Create("circuit")
	defer f1.Close()
	f2, _ := os.Create("pk")
	defer f2.Close()
	f3, _ := os.Create("vk")
	defer f3.Close()
	r1cs.WriteTo(f1)
	if (serialType == "native") {
		pk.WriteTo(f2)
		vk.WriteTo(f3)
	} else if (serialType == "raw") {
		pk.WriteRawTo(f2)
		vk.WriteRawTo(f3)
	} else if (serialType == "cbol") {
		pk.WriteRawTo(f2)
		// enc := cbor.NewEncoder(f2)
		// _ = enc.Encode(pk)
		enc := cbor.NewEncoder(f3)
		_ = enc.Encode(vk)
	}
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}

func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func decode(serialType string) {
	t := time.Now()
	cs := groth16.NewCS(ecc.BN254)
	f1, _ := os.Open("circuit")
	cs.ReadFrom(f1)
	PrintMemUsage()
	timeTrack(t, "deserialize circuit")
	println(cs.GetNbConstraints())

	t = time.Now()
	pk := groth16.NewProvingKey(ecc.BN254)
	f2, _ := os.Open("pk")
	if (serialType == "native" || serialType == "raw") {
		pk.ReadFrom(f2)
	}  else if (serialType == "cbol") {
		pk.ReadFrom(f2)
		// dec := cbor.NewDecoder(f2)
		// _ = dec.Decode(pk)
	}
	PrintMemUsage()
	timeTrack(t, "deserialize pk")

	t = time.Now()
	vk := groth16.NewVerifyingKey(ecc.BN254)
	f3, _ := os.Open("vk")
	if (serialType == "native" || serialType == "raw") {
		vk.ReadFrom(f3)
	}  else if (serialType == "cbol") {
		dec := cbor.NewDecoder(f3)
		_ = dec.Decode(vk)
	}
	PrintMemUsage()
	timeTrack(t, "deserialize vk")

	prove(cs, pk, vk)
}

func main() {
	serialType := "cbol"
	setup(serialType)
	decode(serialType)
}