package webapps

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidHash       = errors.New("invalid hash")
	ErrUserFieldMissing  = errors.New("user field missing")
	ErrAuthDateMissing   = errors.New("auth_date field missing")
	ErrAuthDateInvalid   = errors.New("invalid auth_date")
	ErrDataExpired       = errors.New("data is too old")
	ErrInvalidDataFormat = errors.New("invalid data format")
)

const (
	MaxDataAge = 24 * time.Hour
)

type WebAppUser struct {
	ID                    int    `json:"id"`
	IsBot                 bool   `json:"is_bot"`
	IsPremium             bool   `json:"is_premium"`
	FirstName             string `json:"first_name"`
	LastName              string `json:"last_name"`
	Username              string `json:"username"`
	LanguageCode          string `json:"language_code"`
	AddedToAttachmentMenu bool   `json:"added_to_attachment_menu"`
	AllowsWriteToPm       bool   `json:"allows_write_to_pm"`
	PhotoURL              string `json:"photo_url"`
}

func VerifyWebAppData(telegramInitData, token string) (WebAppUser, error) {
	params, hashValue, err := parseInitData(telegramInitData)
	if err != nil {
		return WebAppUser{}, fmt.Errorf("parsing failed: %w", err)
	}

	if err := validateRequiredFields(params); err != nil {
		return WebAppUser{}, err
	}

	if err := validateAuthTimestamp(params["auth_date"]); err != nil {
		return WebAppUser{}, err
	}

	if err := validateDataSignature(params, hashValue, token); err != nil {
		return WebAppUser{}, err
	}

	return decodeUserData(params["user"])
}

func parseInitData(initData string) (map[string]string, string, error) {
	values, err := url.ParseQuery(initData)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrInvalidDataFormat, err)
	}

	params := make(map[string]string, len(values))
	for key := range values {
		params[key] = values.Get(key)
	}

	return params, params["hash"], nil
}

func validateRequiredFields(params map[string]string) error {
	switch {
	case params["hash"] == "":
		return ErrInvalidHash
	case params["user"] == "":
		return ErrUserFieldMissing
	case params["auth_date"] == "":
		return ErrAuthDateMissing
	}
	return nil
}

func validateAuthTimestamp(authDateStr string) error {
	authTimestamp, err := strconv.ParseInt(authDateStr, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthDateInvalid, err)
	}

	authTime := time.Unix(authTimestamp, 0)
	if time.Since(authTime) > MaxDataAge {
		return ErrDataExpired
	}

	return nil
}

func validateDataSignature(params map[string]string, receivedHash, token string) error {
	dataCheckString := createDataCheckString(params, params["auth_date"])
	expectedHash := computeHMAC(dataCheckString, token)

	fmt.Println(expectedHash, receivedHash)
	if !hmac.Equal([]byte(expectedHash), []byte(receivedHash)) {
		return ErrInvalidHash
	}
	return nil
}

func createDataCheckString(params map[string]string, authDate string) string {
	pairs := make([]string, 0, len(params)+1)

	for k, v := range params {
		if k == "hash" || k == "auth_date" {
			continue
		}
		pairs = append(pairs, k+"="+v)
	}

	pairs = append(pairs, "auth_date="+authDate)
	sort.Strings(pairs)

	return strings.Join(pairs, "\n")
}

func computeHMAC(dataCheckString, token string) string {
	secret := hmac.New(sha256.New, []byte("WebAppData"))
	secret.Write([]byte(token))

	hHash := hmac.New(sha256.New, secret.Sum(nil))
	hHash.Write([]byte(dataCheckString))

	return hex.EncodeToString(hHash.Sum(nil))
}

func decodeUserData(encodedData string) (WebAppUser, error) {
	decodedData, err := url.QueryUnescape(encodedData)
	if err != nil {
		return WebAppUser{}, fmt.Errorf("url unescape failed: %w", err)
	}

	var user WebAppUser
	if err := json.Unmarshal([]byte(decodedData), &user); err != nil {
		return user, fmt.Errorf("json decode failed: %w", err)
	}

	return user, nil
}
