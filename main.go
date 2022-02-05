package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

const N int = 13000000

type Circuit struct {
	A frontend.Variable
	B frontend.Variable
	C frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	var V [N]frontend.Variable
	V[0] = api.Add(api.Mul(circuit.A, circuit.A), circuit.B)
	for i := 1; i < N; i++ {
		V[i] = api.Add(api.Mul(V[i-1], V[i-1]), circuit.B)
	}
	api.Println(V[N-1])
	api.AssertIsEqual(circuit.C, V[N-1])

	return nil
}

func setup() {
	var circuit Circuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		panic("compile failed")
	}

	f, err := os.Create("circuit")
	defer f.Close()
	r1cs.WriteTo(f)

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic("setup failed")
	}

	println(r1cs.GetNbConstraints())
	f2, err := os.Create("pk")
	defer f2.Close()
	pk.WriteRawTo(f2)

	f3, err := os.Create("vk")
	defer f3.Close()
	vk.WriteTo(f3)

	var witness Circuit
	witness.A = 666
	witness.B = 233
	// N = 13000
	// witness.C = "6793544489128382459281307073994348887771341450407551491096489485513352038568"
	// N = 13000000
	witness.C = "11627185319010103288157029572521291604665626512789572484375095826433360489871"

	proof, err := groth16.Prove(r1cs, pk, &witness)
	if err != nil {
		panic("prove failed")
	}

	err = groth16.Verify(proof, vk, &witness)
	if err != nil {
		panic("verification failed")
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

func prove() {
	t := time.Now()
	cs := groth16.NewCS(ecc.BN254)
	f, _ := os.Open("circuit")
	cs.ReadFrom(f)
	PrintMemUsage()
	timeTrack(t, "deserialize circuit")
	println(cs.GetNbConstraints())

	t = time.Now()
	pk := groth16.NewProvingKey(ecc.BN254)
	f2, _ := os.Open("pk")
	pk.ReadFrom(f2)
	PrintMemUsage()
	timeTrack(t, "deserialize pk")

}

func main() {
	// setup()
	prove()
}
