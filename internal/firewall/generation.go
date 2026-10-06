package firewall

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const maximumGenerationSize = 1024

// writerGeneration is root-owned coordination metadata, not directory input,
// renewable authorization or proof of an installed protected floor. The owning
// writer protocol must advance sequence on every transition, keep ready false
// until revoked old variants and new paths are independently verified, and
// never restore an older sequence. No publisher is implemented here yet.
type writerGeneration struct {
	SchemaVersion int    `json:"schema_version"`
	Sequence      uint64 `json:"sequence"`
	FloorHash     string `json:"floor_hash"`
	MappingHash   string `json:"mapping_hash"`
	Ready         bool   `json:"ready"`
}

func decodeWriterGeneration(data []byte) (writerGeneration, error) {
	keys := []string{"schema_version", "sequence", "floor_hash", "mapping_hash", "ready"}
	if err := strictjson.Object(data, keys, nil, maximumGenerationSize); err != nil {
		return writerGeneration{}, err
	}
	var value writerGeneration
	if err := strictjson.Decode(data, &value, maximumGenerationSize); err != nil {
		return writerGeneration{}, err
	}
	if err := value.validate(); err != nil {
		return writerGeneration{}, err
	}
	return value, nil
}

func (g writerGeneration) validate() error {
	validHeader := g.SchemaVersion == 1 && g.Sequence != 0
	validHashes := generationHash(g.FloorHash) && generationHash(g.MappingHash)
	if !validHeader || !validHashes {
		return errors.New("firewall: invalid writer generation")
	}
	return nil
}

func generationHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (g writerGeneration) check(expected writerGeneration) error {
	if err := expected.validate(); err != nil {
		return err
	}
	if err := g.validate(); err != nil {
		return err
	}
	bothReady := expected.Ready && g.Ready
	if !bothReady || g != expected {
		return errors.New("firewall: writer generation is closed or differs")
	}
	return nil
}
