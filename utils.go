package main

import (
  "hash/fnv"
  "encoding/hex"
)

func Hash(text ...string) string {
  h := fnv.New64()
  for _, s := range text {
      h.Write([]byte(s))
  }
  return hex.EncodeToString(h.Sum(nil))
}
