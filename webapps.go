package webapps

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

var (
	HashIsNotValid = errors.New("hash is not valid")
	json           = jsoniter.ConfigCompatibleWithStandardLibrary
)

type WebAppUser struct {
	ID           int    `json:"id"`
	IsBot        bool   `json:"is_bot"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Username     string `json:"username"`
	LanguageCode string `json:"language_code"`
	PhotoUrl     string `json:"photo_url"`
}

func VerifyWebAppData(telegramInitData string, token string) (error, WebAppUser) {
	initData, err := url.ParseQuery(telegramInitData)
	if err != nil {
		return fmt.Errorf("Error parsing data: %s", err), WebAppUser{}
	}

	dataToCheck := []string{}
	for k, v := range initData {
		if k == "hash" {
			continue
		}

		dataToCheck = append(dataToCheck, fmt.Sprintf("%s=%s", k, v[0]))
	}

	sort.Strings(dataToCheck)

	secret := hmac.New(sha256.New, []byte("WebAppData"))
	secret.Write([]byte(token))

	hHash := hmac.New(sha256.New, secret.Sum(nil))
	hHash.Write([]byte(strings.Join(dataToCheck, "\n")))

	hash := hex.EncodeToString(hHash.Sum(nil))

	if initData.Get("hash") != hash {
		return HashIsNotValid, WebAppUser{}
	}

	user := WebAppUser{}
	err = json.Unmarshal([]byte(initData.Get("user")), &user)
	if err != nil {
		return fmt.Errorf("cannot parse user: %w", err), user
	}

	return nil, user
}
