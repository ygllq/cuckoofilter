package cuckoofilter

import (
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"testing"

	xxhash "github.com/cespare/xxhash/v2"
)

func generateRandItems(size int) [][]byte {
	// dp := make(map[uint64]struct{}, size)
	items := make([][]byte, 0, size)
	hash := xxhash.New()
	for i := 0; i < size; i++ {
		hash.Reset()
		hash.Write([]byte(fmt.Sprintf("%x", rand.Uint64())))
		hv := hash.Sum(nil)
		items = append(items, []byte(hex.EncodeToString(hv)))
	}
	return items
}

func TestCuckooFilterInit(t *testing.T) {
	items := [][]byte{
		[]byte("e59cece3b2fa8261"),
		[]byte("189562bad05fb806"),
		[]byte("2630dd729d7b5d95"),
	}

	initSize := uint64(1 << 10)
	cf := New(initSize)

	for _, v := range items {
		err := cf.Add(v)
		if err != nil {
			t.Fatalf("add item into filter failed: %v", err)
		}
	}

	for _, v := range items {
		if !cf.Contain(v) {
			t.Errorf("insert item %s not found!", v)
			return
		}
	}

	// delete all items
	for _, v := range items {
		cf.Delete(v)
	}

	for _, v := range items {
		if cf.Contain(v) {
			t.Errorf("delete item %s failed!", v)
			return
		}
	}
}

func TestCuckooFilterAdd(t *testing.T) {
	initSize := uint64(1 << 20)
	cf := New(initSize)

	testSize := initSize * 9 / 10
	items := generateRandItems(int(testSize))
	for _, val := range items {
		n1 := cf.Count()
		err := cf.Add(val)
		if err != nil {
			t.Fatalf("add item into filter failed: %v", err)
		}
		n2 := cf.Count()
		if n2 != n1+1 {
			t.Fatalf("add item but count not correctly add one")
		}
	}
	for idx, v := range items {
		if !cf.Contain(v) {
			t.Errorf("insert item %d - %s not found!", idx, v)
			return
		}
	}
	// for _, v := range items {
	// 	cf.Delete([]byte(v))
	// }
	t.Logf("Total kicks is %d\n", cf.kicks)
}

func BenchmarkCuckooFilterAdd(b *testing.B) {
	initSize := uint64(1 << 20)
	cf := New(initSize)

	items := generateRandItems(int(initSize * 8 / 10))
	n := len(items)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cf.Add([]byte(items[i%n]))
	}
}

func FuzzCuckooFilter(f *testing.F) {
	hash := xxhash.New()
	testSize := 20
	for i := 0; i < testSize; i++ {
		hash.Reset()
		hash.Write([]byte(fmt.Sprintf("%x", rand.Uint64())))
		hv := hash.Sum(nil)
		f.Add(hv)
	}

	initSize := uint64(1 << 20)
	cf := New(initSize)

	f.Fuzz(func(t *testing.T, v []byte) {
		bc := cf.Count()
		if err := cf.Add(v); err != nil {
			t.Fatal(err)
		}
		ba := cf.Count()
		if ba != bc+1 {
			t.Errorf("add success but count not correct.")
			return
		}
		if !cf.Contain(v) {
			fp := fingerprint(v)
			t.Errorf("expect add item: %s exists, but not: %04x", v, fp)
			return
		}
	})
}

func TestGetNewPow2(t *testing.T) {
	tests := []struct {
		Input  uint64
		Expect uint64
	}{
		{0, 0},
		{1, 1},
		{9, 16},
		{15, 16},
		{123, 128},
		{129, 256},
		{1000, 1024},
		{1024, 1024},
		{1025, 2048},
	}

	for _, tc := range tests {
		np := getNextPow2(tc.Input)
		if np != tc.Expect {
			t.Errorf("For %d expect: %d, got: %d\n", tc.Input, tc.Expect, np)
		}
	}
}
