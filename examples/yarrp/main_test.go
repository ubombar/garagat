package main

import (
	"math/rand/v2"
	"testing"
)

func TestPermutation(t *testing.T) {
	for _, n := range []uint64{1, 2, 3, 7, 100, 1000} {
		p := newPermutation(n, rand.New(rand.NewPCG(1, 2)))
		seen := map[uint64]bool{}
		for {
			v, ok := p.next()
			if !ok {
				break
			}
			if v >= n || seen[v] {
				t.Fatalf("n=%d: bad value %d", n, v)
			}
			seen[v] = true
		}
		if uint64(len(seen)) != n {
			t.Errorf("n=%d: got %d values", n, len(seen))
		}
	}
}

func TestPoisson(t *testing.T) {
	var sum float64
	for k := 0; k < 100; k++ {
		sum += poissonPMF(float64(k), 8)
	}
	if sum < 0.999 || sum > 1.001 {
		t.Errorf("pmf sums to %g", sum)
	}
}
