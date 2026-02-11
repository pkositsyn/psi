package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sync"
)

func GenerateHMACKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func HMAC(p *sync.Pool, key, data []byte) string {
	var h hash.Hash
	if p == nil {
		h = hmac.New(sha256.New, key)
	} else {
		h = p.Get().(hash.Hash)
	}
	h.Write(data)
	sum := h.Sum(nil)
	if p != nil {
		h.Reset()
		p.Put(h)
	}
	return hex.EncodeToString(sum)
}
