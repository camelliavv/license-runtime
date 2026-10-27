package runtime

import "github.com/camelliavv/license-contract"

func encodeBase64(value []byte) string          { return contract.EncodeBase64URL(value) }
func decodeBase64(value string) ([]byte, error) { return contract.DecodeBase64URL(value) }
