package runtime

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

var b64 = base64.RawURLEncoding.Strict()

const (
	// CipherFormatVersion 是加密数据封装格式版本。
	CipherFormatVersion = 1
	// CipherAlgorithm 是数据加密算法名称。
	CipherAlgorithm = "AES-256-GCM"
)

// KeyProtector 是数据加密密钥的保护边界。生产环境的加密狗适配器应在
// 设备内部完成密钥包装和解包；软件适配器只用于迁移和测试，不能抵御客户 root。
type KeyProtector interface {
	// Name 返回保护器名称，用于绑定加密数据和密钥来源。
	Name() string
	// WrapKey 包装一个随机生成的数据加密密钥。
	WrapKey(context.Context, []byte) ([]byte, error)
	// UnwrapKey 解包加密数据中保存的数据加密密钥。
	UnwrapKey(context.Context, []byte) ([]byte, error)
}

// DisabledProtector 表示未配置硬件或外部密钥，所有密钥操作都会失败。
type DisabledProtector struct{}

// Name 返回 disabled。
func (DisabledProtector) Name() string { return "disabled" }

// WrapKey 拒绝在没有保护器时包装密钥。
func (DisabledProtector) WrapKey(context.Context, []byte) ([]byte, error) {
	return nil, ErrHardwareRequired
}

// UnwrapKey 拒绝在没有保护器时解包密钥。
func (DisabledProtector) UnwrapKey(context.Context, []byte) ([]byte, error) {
	return nil, ErrHardwareRequired
}

// Dongle 定义加密狗适配器需要提供的密钥操作。
type Dongle interface {
	// DeviceID 返回当前硬件设备标识。
	DeviceID(context.Context) (string, error)
	// WrapKey 在硬件设备中包装数据密钥。
	WrapKey(context.Context, []byte) ([]byte, error)
	// UnwrapKey 在硬件设备中解包数据密钥。
	UnwrapKey(context.Context, []byte) ([]byte, error)
}

// DongleProtector 将 Dongle 适配为 KeyProtector。
type DongleProtector struct{ Dongle Dongle }

// Name 返回 hardware-dongle。
func (p DongleProtector) Name() string { return "hardware-dongle" }

// WrapKey 委托加密狗包装数据密钥。
func (p DongleProtector) WrapKey(ctx context.Context, key []byte) ([]byte, error) {
	if p.Dongle == nil {
		return nil, ErrHardwareRequired
	}
	return p.Dongle.WrapKey(ctx, key)
}

// UnwrapKey 委托加密狗解包数据密钥。
func (p DongleProtector) UnwrapKey(ctx context.Context, wrapped []byte) ([]byte, error) {
	if p.Dongle == nil {
		return nil, ErrHardwareRequired
	}
	return p.Dongle.UnwrapKey(ctx, wrapped)
}

// SoftwareProtector 使用外部注入的 32 字节密钥保护数据密钥。
type SoftwareProtector struct{ rootKey []byte }

// NewSoftwareProtector 创建软件迁移型密钥保护器。
func NewSoftwareProtector(rootKey []byte) (SoftwareProtector, error) {
	if len(rootKey) != 32 {
		return SoftwareProtector{}, fmt.Errorf("software protector key must be 32 bytes")
	}
	return SoftwareProtector{rootKey: append([]byte(nil), rootKey...)}, nil
}

// Name 返回 software-external-key。
func (p SoftwareProtector) Name() string { return "software-external-key" }

// WrapKey 使用 AES-GCM 包装数据密钥。
func (p SoftwareProtector) WrapKey(ctx context.Context, key []byte) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(p.rootKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, key, []byte("license/key-wrap/v1"))
	return append(nonce, sealed...), nil
}

// UnwrapKey 使用 AES-GCM 解包数据密钥。
func (p SoftwareProtector) UnwrapKey(ctx context.Context, wrapped []byte) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(p.rootKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < gcm.NonceSize() {
		return nil, ErrKeyUnavailable
	}
	key, err := gcm.Open(nil, wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():], []byte("license/key-wrap/v1"))
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	return key, nil
}

// EncryptedBlob 保存加密数据、随机 nonce 和被保护的数据密钥。
type EncryptedBlob struct {
	Version    int    `json:"version"`     // 加密格式版本。
	Algorithm  string `json:"algorithm"`   // 加密算法。
	Protector  string `json:"protector"`   // 密钥保护器名称。
	Nonce      string `json:"nonce"`       // Base64URL 编码的 nonce。
	WrappedKey string `json:"wrapped_key"` // Base64URL 编码的包装密钥。
	Ciphertext string `json:"ciphertext"`  // Base64URL 编码的密文。
	AADDigest  string `json:"aad_sha256"`  // AAD 的 SHA-256 摘要。
}

// Encrypt 使用随机 DEK 和 AES-256-GCM 加密明文。
func Encrypt(ctx context.Context, protector KeyProtector, plaintext, aad []byte) (EncryptedBlob, error) {
	if protector == nil {
		return EncryptedBlob{}, ErrHardwareRequired
	}
	if len(plaintext) > 64<<20 {
		return EncryptedBlob{}, fmt.Errorf("plaintext exceeds 64 MiB limit")
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return EncryptedBlob{}, err
	}
	wrapped, err := protector.WrapKey(ctx, dek)
	if err != nil {
		return EncryptedBlob{}, err
	}
	if len(wrapped) == 0 {
		return EncryptedBlob{}, ErrKeyUnavailable
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return EncryptedBlob{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedBlob{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedBlob{}, err
	}
	digest := sha256.Sum256(aad)
	return EncryptedBlob{Version: CipherFormatVersion, Algorithm: CipherAlgorithm, Protector: protector.Name(), Nonce: b64.EncodeToString(nonce), WrappedKey: b64.EncodeToString(wrapped), Ciphertext: b64.EncodeToString(gcm.Seal(nil, nonce, plaintext, aad)), AADDigest: b64.EncodeToString(digest[:])}, nil
}

// Marshal 将加密数据编码为 JSON。
func (b EncryptedBlob) Marshal() ([]byte, error) { return json.Marshal(b) }

// ParseEncryptedBlob 解析加密数据并检查其格式版本。
func ParseEncryptedBlob(raw []byte) (EncryptedBlob, error) {
	var blob EncryptedBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return EncryptedBlob{}, err
	}
	if blob.Version != CipherFormatVersion || blob.Algorithm != CipherAlgorithm || blob.Protector == "" {
		return EncryptedBlob{}, fmt.Errorf("unsupported encrypted blob")
	}
	return blob, nil
}

// Decrypt 验证 AAD 后解包数据密钥并解密明文。
func (b EncryptedBlob) Decrypt(ctx context.Context, protector KeyProtector, aad []byte) ([]byte, error) {
	if protector == nil {
		return nil, ErrHardwareRequired
	}
	if b.Protector != protector.Name() {
		return nil, fmt.Errorf("encrypted blob requires protector %q", b.Protector)
	}
	digest := sha256.Sum256(aad)
	expected, err := b64.DecodeString(b.AADDigest)
	if err != nil || len(expected) != sha256.Size || string(expected) != string(digest[:]) {
		return nil, fmt.Errorf("AAD does not match encrypted blob")
	}
	nonce, err := b64.DecodeString(b.Nonce)
	if err != nil {
		return nil, err
	}
	wrapped, err := b64.DecodeString(b.WrappedKey)
	if err != nil {
		return nil, err
	}
	ciphertext, err := b64.DecodeString(b.Ciphertext)
	if err != nil {
		return nil, err
	}
	dek, err := protector.UnwrapKey(ctx, wrapped)
	if err != nil {
		return nil, err
	}
	if len(dek) != 32 {
		return nil, ErrKeyUnavailable
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted blob nonce")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypted blob authentication failed: %w", err)
	}
	return plaintext, nil
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
