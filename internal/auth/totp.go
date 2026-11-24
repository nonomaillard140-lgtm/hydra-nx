package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

func NewTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) < 10 {
		return "", fmt.Errorf("secret TOTP invalide")
	}
	counter := uint64(at.Unix() / 30)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000), nil
}

func VerifyTOTP(secret, code string, at time.Time) bool {
	code = strings.TrimSpace(code)
	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		expected, err := TOTPCode(secret, at.Add(offset))
		if err == nil && hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

func NewRecoveryCodes() ([]string, string, error) {
	codes := make([]string, 8)
	hashes := make([]string, len(codes))
	for i := range codes {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, "", err
		}
		codes[i] = base64.RawURLEncoding.EncodeToString(buf)
		sum := sha256.Sum256([]byte(codes[i]))
		hashes[i] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	encoded, err := json.Marshal(hashes)
	return codes, string(encoded), err
}

func ConsumeRecoveryCode(userRecoveryJSON, code string) (string, bool) {
	var hashes []string
	if json.Unmarshal([]byte(userRecoveryJSON), &hashes) != nil {
		return userRecoveryJSON, false
	}
	sum := sha256.Sum256([]byte(code))
	needle := base64.RawURLEncoding.EncodeToString(sum[:])
	for i, hash := range hashes {
		if hmac.Equal([]byte(hash), []byte(needle)) {
			hashes = append(hashes[:i], hashes[i+1:]...)
			encoded, err := json.Marshal(hashes)
			return string(encoded), err == nil
		}
	}
	return userRecoveryJSON, false
}

func TOTPURI(secret, username, issuer string) string {
	return "otpauth://totp/" + issuer + ":" + username + "?secret=" + secret + "&issuer=" + issuer + "&digits=6&period=30&algorithm=SHA1"
}

func ValidateCodeFormat(code string) bool {
	if len(code) != 6 {
		return false
	}
	_, err := strconv.Atoi(code)
	return err == nil
}
