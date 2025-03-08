package webapps

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"
)

func TestParseInitData(t *testing.T) {
	tests := []struct {
		name        string
		initData    string
		wantParams  map[string]string
		wantHash    string
		expectError bool
	}{
		{
			name:     "Valid init data",
			initData: "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A123456789%2C%22first_name%22%3A%22Test%22%2C%22last_name%22%3A%22User%22%2C%22username%22%3A%22testuser%22%2C%22language_code%22%3A%22en%22%7D&auth_date=1625097522&hash=abc123",
			wantParams: map[string]string{
				"query_id":  "AAHdF6IQAAAAAN0XohDhrOrc",
				"user":      "{\"id\":123456789,\"first_name\":\"Test\",\"last_name\":\"User\",\"username\":\"testuser\",\"language_code\":\"en\"}",
				"auth_date": "1625097522",
				"hash":      "abc123",
			},
			wantHash:    "abc123",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, hash, err := parseInitData(tt.initData)

			if (err != nil) != tt.expectError {
				t.Errorf("parseInitData() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if tt.expectError {
				return
			}

			if hash != tt.wantHash {
				t.Errorf("parseInitData() hash = %v, want %v", hash, tt.wantHash)
			}

			for k, v := range tt.wantParams {
				if params[k] != v {
					t.Errorf("parseInitData() params[%s] = %v, want %v", k, params[k], v)
				}
			}
		})
	}
}

func TestValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]string
		wantErr error
	}{
		{
			name: "All required fields present",
			params: map[string]string{
				"hash":      "abc123",
				"user":      "{\"id\":123456789}",
				"auth_date": "1625097522",
			},
			wantErr: nil,
		},
		{
			name: "Missing hash",
			params: map[string]string{
				"user":      "{\"id\":123456789}",
				"auth_date": "1625097522",
			},
			wantErr: ErrInvalidHash,
		},
		{
			name: "Empty hash",
			params: map[string]string{
				"hash":      "",
				"user":      "{\"id\":123456789}",
				"auth_date": "1625097522",
			},
			wantErr: ErrInvalidHash,
		},
		{
			name: "Missing user",
			params: map[string]string{
				"hash":      "abc123",
				"auth_date": "1625097522",
			},
			wantErr: ErrUserFieldMissing,
		},
		{
			name: "Missing auth_date",
			params: map[string]string{
				"hash": "abc123",
				"user": "{\"id\":123456789}",
			},
			wantErr: ErrAuthDateMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequiredFields(tt.params)
			if err != tt.wantErr {
				t.Errorf("validateRequiredFields() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAuthTimestamp(t *testing.T) {
	now := time.Now().Unix()
	oldTimestamp := now - int64(MaxDataAge.Seconds()) - 3600

	tests := []struct {
		name     string
		authDate string
		wantErr  error
	}{
		{
			name:     "Valid recent timestamp",
			authDate: fmt.Sprintf("%d", now-1000),
			wantErr:  nil,
		},
		{
			name:     "Expired timestamp",
			authDate: fmt.Sprintf("%d", oldTimestamp),
			wantErr:  ErrDataExpired,
		},
		{
			name:     "Invalid timestamp format",
			authDate: "not-a-number",
			wantErr:  ErrAuthDateInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthTimestamp(tt.authDate)
			if err == nil && tt.wantErr != nil {
				t.Errorf("validateAuthTimestamp() error = nil, wantErr %v", tt.wantErr)
			}
			if err != nil && tt.wantErr == nil {
				t.Errorf("validateAuthTimestamp() error = %v, wantErr nil", err)
			}
			if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				if tt.wantErr == ErrAuthDateInvalid && err.Error()[:len(ErrAuthDateInvalid.Error())] == ErrAuthDateInvalid.Error() {
				} else {
					t.Errorf("validateAuthTimestamp() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestCreateDataCheckString(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]string
		authDate string
		want     string
	}{
		{
			name: "Basic params",
			params: map[string]string{
				"query_id": "AAHdF6IQAAAAAN0XohDhrOrc",
				"user":     "{\"id\":123456789}",
				"hash":     "abc123",
			},
			authDate: "1625097522",
			want:     "auth_date=1625097522\nquery_id=AAHdF6IQAAAAAN0XohDhrOrc\nuser={\"id\":123456789}",
		},
		{
			name: "Should skip hash but include auth_date",
			params: map[string]string{
				"hash":      "abc123",
				"auth_date": "1625097522",
				"user":      "{\"id\":123456789}",
			},
			authDate: "1625097522",
			want:     "auth_date=1625097522\nuser={\"id\":123456789}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createDataCheckString(tt.params, tt.authDate)
			if got != tt.want {
				t.Errorf("createDataCheckString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeUserData(t *testing.T) {
	tests := []struct {
		name        string
		encodedData string
		want        WebAppUser
		expectError bool
	}{
		{
			name:        "Valid user data",
			encodedData: "%7B%22id%22%3A123456%2C%22first_name%22%3A%22John%22%2C%22last_name%22%3A%22Doe%22%2C%22username%22%3A%22johndoe%22%2C%22language_code%22%3A%22en%22%7D",
			want: WebAppUser{
				ID:           123456,
				FirstName:    "John",
				LastName:     "Doe",
				Username:     "johndoe",
				LanguageCode: "en",
			},
			expectError: false,
		},
		{
			name:        "Invalid JSON format",
			encodedData: "%7Binvalid-json%7D",
			want:        WebAppUser{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeUserData(tt.encodedData)

			if (err != nil) != tt.expectError {
				t.Errorf("decodeUserData() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError {
				if got.ID != tt.want.ID ||
					got.FirstName != tt.want.FirstName ||
					got.LastName != tt.want.LastName ||
					got.Username != tt.want.Username ||
					got.LanguageCode != tt.want.LanguageCode {
					t.Errorf("decodeUserData() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestComputeHMAC(t *testing.T) {
	tests := []struct {
		name            string
		dataCheckString string
		token           string
	}{
		{
			name:            "Basic test",
			dataCheckString: "auth_date=1625097522\nuser={\"id\":123456789}",
			token:           "test_token",
		},
		{
			name:            "Empty data check string",
			dataCheckString: "",
			token:           "test_token",
		},
		{
			name:            "Empty token",
			dataCheckString: "auth_date=1625097522",
			token:           "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := hmac.New(sha256.New, []byte("WebAppData"))
			secret.Write([]byte(tt.token))

			hHash := hmac.New(sha256.New, secret.Sum(nil))
			hHash.Write([]byte(tt.dataCheckString))

			expected := hex.EncodeToString(hHash.Sum(nil))
			got := computeHMAC(tt.dataCheckString, tt.token)

			if got != expected {
				t.Errorf("computeHMAC() = %v, want %v", got, expected)
			}
		})
	}
}

func TestValidateDataSignature(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]string
		token   string
		wantErr error
	}{
		{
			name: "Valid signature",
			params: map[string]string{
				"user":      "{\"id\":123456789}",
				"auth_date": "1625097522",
			},
			token:   "test_token",
			wantErr: nil,
		},
		{
			name: "Invalid signature",
			params: map[string]string{
				"user":      "{\"id\":123456789}",
				"auth_date": "1625097522",
			},
			token:   "wrong_token",
			wantErr: ErrInvalidHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataCheckString := createDataCheckString(tt.params, tt.params["auth_date"])
			correctHash := computeHMAC(dataCheckString, tt.token)

			var receivedHash string
			if tt.wantErr == nil {
				receivedHash = correctHash
			} else {
				receivedHash = "invalid_hash_value"
			}

			err := validateDataSignature(tt.params, receivedHash, tt.token)
			if (err != nil && tt.wantErr == nil) || (err == nil && tt.wantErr != nil) {
				t.Errorf("validateDataSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyWebAppData_Integration(t *testing.T) {
	token := "test_token_12345"
	user := WebAppUser{
		ID:           12345,
		FirstName:    "Test",
		LastName:     "User",
		Username:     "testuser",
		LanguageCode: "ru",
	}

	userJSON, _ := json.Marshal(user)
	userEncoded := url.QueryEscape(string(userJSON))

	authDate := fmt.Sprintf("%d", time.Now().Unix())

	params := map[string]string{
		"user":      string(userJSON),
		"auth_date": authDate,
	}

	dataCheckString := createDataCheckString(params, authDate)

	hash := computeHMAC(dataCheckString, token)

	initData := "auth_date=" + authDate + "&user=" + userEncoded + "&hash=" + hash

	gotUser, err := VerifyWebAppData(initData, token)
	if err != nil {
		t.Errorf("VerifyWebAppData() with valid token error = %v", err)
	}
	if gotUser.ID != user.ID || gotUser.Username != user.Username {
		t.Errorf("VerifyWebAppData() = %v, want %v", gotUser, user)
	}

	_, err = VerifyWebAppData(initData, "wrong_token")
	if err == nil {
		t.Error("VerifyWebAppData() with invalid token should return error")
	}
}

func TestVerifyWebAppData_MissingFields(t *testing.T) {
	tests := []struct {
		name     string
		initData string
		token    string
		wantErr  error
	}{
		{
			name:     "Missing hash",
			initData: "auth_date=1625097522&user=%7B%22id%22%3A123456%7D",
			token:    "test_token",
			wantErr:  ErrInvalidHash,
		},
		{
			name:     "Missing user",
			initData: "auth_date=1625097522&hash=abc123",
			token:    "test_token",
			wantErr:  ErrUserFieldMissing,
		},
		{
			name:     "Missing auth_date",
			initData: "user=%7B%22id%22%3A123456%7D&hash=abc123",
			token:    "test_token",
			wantErr:  ErrAuthDateMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyWebAppData(tt.initData, tt.token)
			if err == nil {
				t.Errorf("VerifyWebAppData() expected error, got nil")
				return
			}

			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("VerifyWebAppData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyWebAppData_InvalidUserJSON(t *testing.T) {
	invalidUserJSON := url.QueryEscape("{invalid-json}")
	authDate := fmt.Sprintf("%d", time.Now().Unix())

	initData := "auth_date=" + authDate + "&user=" + invalidUserJSON + "&hash=abc123"

	_, err := VerifyWebAppData(initData, "test_token")
	if err == nil {
		t.Errorf("VerifyWebAppData() with invalid user JSON expected error, got nil")
	}
}

func TestVerifyWebAppData_InvalidAuthDate(t *testing.T) {
	user := WebAppUser{ID: 12345}
	userJSON, _ := json.Marshal(user)
	userEncoded := url.QueryEscape(string(userJSON))

	initData := "auth_date=not-a-timestamp&user=" + userEncoded + "&hash=abc123"

	_, err := VerifyWebAppData(initData, "test_token")
	if err == nil {
		t.Errorf("VerifyWebAppData() with invalid auth_date expected error, got nil")
	}

	if !errors.Is(err, ErrAuthDateInvalid) {
		t.Errorf("VerifyWebAppData() error = %v, want error containing %v", err, ErrAuthDateInvalid)
	}
}
