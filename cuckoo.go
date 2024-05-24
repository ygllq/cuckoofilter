package cuckoofilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	xxhash "github.com/cespare/xxhash/v2"
)

var (
	ErrMaxRetry = errors.New("kick out achieved max retry times")
	ErrKickNone = errors.New("Cannot find the kick entry")
)

type Filter struct {
	size     uint64
	snum     uint64
	count    uint64
	maxRetry int
	kicks    int
	kickBack int

	slots []uint64
}

func getNextPow2(n uint64) uint64 {
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	n++
	return uint64(n)
}

func New(num uint64) *Filter {
	snum := getNextPow2(num / 4)
	if snum == 0 {
		snum = 1
	}
	size := snum * 4
	return &Filter{
		snum:     snum,
		size:     size,
		slots:    make([]uint64, snum),
		maxRetry: 200,
	}
}

var (
	fph = crc32.NewIEEE()
	idh = xxhash.New()
)

func fingerprint(val []byte) uint16 {
	fph.Reset()
	fph.Write(val)
	hv := fph.Sum32()
	fp := uint16(hv)
	// this library use 0 to identify slot is empty
	// so fingerprint cannot be 0
	if fp == 0 {
		fp = uint16(hv>>16) ^ uint16(hv)
	}
	return fp
}

func hashv(val []byte) uint64 {
	idh.Reset()
	_, err := idh.Write(val)
	if err != nil {
		panic(err)
	}
	return idh.Sum64()
}

func u16bytes(v uint16) []byte {
	return []byte{byte(uint8(v >> 8)), byte(uint8(v))}
}

func lookup(slot uint64, fingerprint uint16) bool {
	for i := 0; i < 4; i++ {
		if uint16(slot>>(i*16)) == fingerprint {
			return true
		}
	}
	return false
}

func (cf *Filter) insert(idx uint64, fingerprint uint16) bool {
	if lookup(cf.slots[idx], fingerprint) {
		return true
	}
	slot := cf.slots[idx]
	for i := 0; i < 4; i++ {
		if uint16(slot>>(i*16)) != 0 {
			continue
		}
		slot |= uint64(fingerprint) << (i * 16)
		cf.slots[idx] = slot
		return true
	}
	return false
}

var masks = []uint64{
	0xFFFFFFFFFFFF0000,
	0xFFFFFFFF0000FFFF,
	0xFFFF0000FFFFFFFF,
	0x0000FFFFFFFFFFFF,
}

func (cf *Filter) remove(idx uint64, fingerprint uint16) bool {
	slot := cf.slots[idx]
	for i := 0; i < 4; i++ {
		if uint16(slot>>(i*16)) != fingerprint {
			continue
		}
		cf.slots[idx] = slot & masks[i]
		return true
	}
	return false
}

func (cf *Filter) isFull(idx uint64) bool {
	slot := cf.slots[idx]
	for i := 0; i < 4; i++ {
		if slot&^masks[i] == 0 {
			return false
		}
	}
	return true
}

func slotIndex(slot uint64, fp uint16) int {
	for i := 0; i < 4; i++ {
		if uint16(slot>>(i*16)) == fp {
			return i
		}
	}
	return -1
}

func (cf *Filter) kickOut(idx uint64, fingerprint uint16, n int) error {
	if n >= cf.maxRetry {
		return ErrMaxRetry
	}
	if !cf.isFull(idx) {
		cf.insert(idx, fingerprint)
		return nil
	}

	cf.kicks++

	slot := cf.slots[idx]
	fp := uint16(slot >> 48)
	cf.slots[idx] = slot<<16 | uint64(fingerprint)
	// si := slotIndex(slot, fingerprint)
	// if si >= 0 {
	// 	cf.kickBack++
	// }
	// // the kick element index
	// k := uint8(fingerprint & 0x03)
	// if int(k) == si {
	// 	k = uint8((si + 1) % 4)
	// }
	// // get the kick element's fingerprint
	// fp := uint16((slot >> (k * 16)) & 0xFFFF)
	// // store replaced fingerprint
	// cf.slots[idx] = (slot & masks[k]) | uint64(fingerprint)<<(k*16)
	// // calculate the next slot to kick out
	nextIndex := idx ^ (hashv(u16bytes(fp)) % cf.snum)
	return cf.kickOut(nextIndex, fp, n+1)
}

const checkItem = "741790f547e1fe42"

func (cf *Filter) Add(item []byte) error {
	fp := fingerprint(item)
	h1 := hashv(item) % cf.snum
	h2 := h1 ^ (hashv(u16bytes(fp)) % cf.snum)
	if cf.insert(h1, fp) {
		cf.count++
		return nil
	}
	if cf.insert(h2, fp) {
		cf.count++
		return nil
	}
	h := h1
	if (h1^h2)&0x01 == 0 {
		h = h2
	}
	err := cf.kickOut(h, fp, 0)
	if err != nil {
		return fmt.Errorf("kick out error, max: %d, %w", cf.kicks, err)
	}
	cf.count++
	return nil
}

func (cf *Filter) Contain(item []byte) bool {
	fp := fingerprint(item)
	h1 := hashv(item) % cf.snum
	if lookup(cf.slots[h1], fp) {
		return true
	}
	h2 := h1 ^ (hashv(u16bytes(fp)) % cf.snum)
	if lookup(cf.slots[h2], fp) {
		return true
	}
	return false
}

func (cf *Filter) Delete(item []byte) {
	fp := fingerprint(item)
	h1 := hashv(item) % cf.snum
	if cf.remove(h1, fp) {
		cf.count--
		return
	}
	h2 := h1 ^ (hashv(u16bytes(fp)) % cf.snum)
	if cf.remove(h2, fp) {
		cf.count--
		return
	}
}

func (cf *Filter) Size() uint64 {
	return cf.snum
}

func (cf *Filter) Count() uint64 {
	return cf.count
}

func (cf *Filter) Dump(writer io.Writer) error {
	buf := make([]byte, 0, cf.size)
	for _, slot := range cf.slots {
		buf = binary.LittleEndian.AppendUint64(buf, slot)
	}
	_, err := writer.Write(buf)
	return err
}
