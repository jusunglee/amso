package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	baseURL = "https://katalk.kakao.com"

	DefaultAgent     = "mac"
	DefaultVersion   = "26.1.4"
	DefaultOSVersion = "26.2"
	DefaultLanguage  = "ko"
)

// LoginRequest contains the credentials and device info for a KakaoTalk login.
type LoginRequest struct {
	Email      string
	Password   string
	DeviceUUID string
	DeviceName string
	Agent      string // "win32" or "android"
	Version    string // e.g. "3.2.3"
	OSVersion  string
	Language   string
	Forced     bool // force login even if another device is logged in
}

// LoginResponse contains tokens and user info returned by a successful login.
type LoginResponse struct {
	Status               int    `json:"status"`
	AccessToken          string `json:"access_token"`
	RefreshToken         string `json:"refresh_token"`
	UserID               int64  `json:"userId"`
	CountryISO           string `json:"countryIso"`
	CountryCode          string `json:"countryCode"`
	AccountID            int64  `json:"accountId"`
	ServerTime           int64  `json:"server_time"`
	StatusMessage        string `json:"statusMessage"`
	TokenType            string `json:"token_type"`
	AutoLoginAccountID   string `json:"autoLoginAccountId"`
	DisplayAccountID     string `json:"displayAccountId"`
	MainDeviceAgentName  string `json:"mainDeviceAgentName"`
	MainDeviceAppVersion string `json:"mainDeviceAppVersion"`
}

func defaults(req LoginRequest) (agent, version, osVersion, language string) {
	agent = req.Agent
	if agent == "" {
		agent = DefaultAgent
	}
	version = req.Version
	if version == "" {
		version = DefaultVersion
	}
	osVersion = req.OSVersion
	if osVersion == "" {
		osVersion = DefaultOSVersion
	}
	language = req.Language
	if language == "" {
		language = DefaultLanguage
	}
	return
}

// getUserAgent builds the User-Agent string for KakaoTalk auth requests.
// "KT/{version} Wd/{osVersion} {language}" for win32
// "KT/{version} Mc/{osVersion} {language}" for mac
// "KT/{version} An/{osVersion} {language}" for android
func getUserAgent(agent, version, osVersion, language string) string {
	var osPrefix string
	switch agent {
	case "android":
		osPrefix = "An"
	case "mac":
		osPrefix = "Mc"
	default:
		osPrefix = "Wd"
	}
	return fmt.Sprintf("KT/%s %s/%s %s", version, osPrefix, osVersion, language)
}

// Login performs HTTP authentication against KakaoTalk and returns tokens.
func Login(req LoginRequest) (*LoginResponse, error) {
	agent, version, osVersion, language := defaults(req)

	form := url.Values{
		"email":       {req.Email},
		"password":    {req.Password},
		"device_uuid": {req.DeviceUUID},
		"device_name": {req.DeviceName},
		"forced":      {fmt.Sprintf("%t", req.Forced)},
	}

	endpoint := fmt.Sprintf("%s/%s/account/login.json", baseURL, agent)
	body, err := doAuthRequest(endpoint, form, agent, version, osVersion, language, req.Email, req.DeviceUUID)
	if err != nil {
		return nil, fmt.Errorf("auth: login: %w", err)
	}

	var loginResp LoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return nil, fmt.Errorf("auth: parse response: %w (body: %s)", err, string(body))
	}

	if loginResp.Status != 0 {
		return &loginResp, fmt.Errorf("auth: login failed with status %d (body: %s)", loginResp.Status, string(body))
	}

	return &loginResp, nil
}

// doAuthRequest sends a POST request with proper KakaoTalk auth headers.
func doAuthRequest(endpoint string, form url.Values, agent, version, osVersion, language, email, deviceUUID string) ([]byte, error) {
	userAgent := getUserAgent(agent, version, osVersion, language)
	xvc := ComputeXVC(agent, userAgent, email, deviceUUID)

	httpReq, err := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("A", fmt.Sprintf("%s/%s/%s", agent, version, language))
	httpReq.Header.Set("X-VC", xvc)
	httpReq.Header.Set("User-Agent", userAgent)
	httpReq.Header.Set("Accept", "*/*")
	httpReq.Header.Set("Accept-Language", language)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// AuthClient holds configuration for device registration API calls.
type AuthClient struct {
	Agent      string
	Version    string
	OSVersion  string
	Language   string
	Email      string
	Password   string
	DeviceUUID string
	DeviceName string
}

// NewAuthClient creates an AuthClient with defaults filled in.
func NewAuthClient(email, password, deviceUUID, deviceName string) *AuthClient {
	return &AuthClient{
		Agent:      DefaultAgent,
		Version:    DefaultVersion,
		OSVersion:  DefaultOSVersion,
		Language:   DefaultLanguage,
		Email:      email,
		Password:   password,
		DeviceUUID: deviceUUID,
		DeviceName: deviceName,
	}
}

func (ac *AuthClient) post(api string, extra url.Values) ([]byte, error) {
	form := url.Values{
		"email":       {ac.Email},
		"password":    {ac.Password},
		"device_uuid": {ac.DeviceUUID},
		"device_name": {ac.DeviceName},
	}
	for k, v := range extra {
		form[k] = v
	}
	endpoint := fmt.Sprintf("%s/%s/account/%s", baseURL, ac.Agent, api)
	return doAuthRequest(endpoint, form, ac.Agent, ac.Version, ac.OSVersion, ac.Language, ac.Email, ac.DeviceUUID)
}

// RequestPasscode requests a device verification passcode be sent to the user's phone.
func (ac *AuthClient) RequestPasscode() ([]byte, error) {
	return ac.post("request_passcode.json", nil)
}

// RegisterDevice submits the verification passcode to register this device.
func (ac *AuthClient) RegisterDevice(passcode string, permanent bool) ([]byte, error) {
	return ac.post("register_device.json", url.Values{
		"passcode":  {passcode},
		"permanent": {fmt.Sprintf("%t", permanent)},
	})
}

// RequestPasscode requests a device verification passcode be sent to the user.
// Deprecated: Use AuthClient.RequestPasscode() instead.
func RequestPasscode(agent, email, password, deviceUUID, deviceName string) error {
	ac := NewAuthClient(email, password, deviceUUID, deviceName)
	if agent != "" {
		ac.Agent = agent
	}
	body, err := ac.RequestPasscode()
	if err != nil {
		return fmt.Errorf("auth: request passcode: %w", err)
	}

	var result struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("auth: parse passcode response: %w (body: %s)", err, string(body))
	}
	if result.Status != 0 {
		return fmt.Errorf("auth: request passcode failed with status %d (body: %s)", result.Status, string(body))
	}
	return nil
}

// RegisterDevice submits the verification passcode to register this device.
// Deprecated: Use AuthClient.RegisterDevice() instead.
func RegisterDevice(agent, email, password, deviceUUID, deviceName, passcode string) error {
	ac := NewAuthClient(email, password, deviceUUID, deviceName)
	if agent != "" {
		ac.Agent = agent
	}
	body, err := ac.RegisterDevice(passcode, true)
	if err != nil {
		return fmt.Errorf("auth: register device: %w", err)
	}

	var result struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("auth: parse register response: %w (body: %s)", err, string(body))
	}
	if result.Status != 0 {
		return fmt.Errorf("auth: register device failed with status %d (body: %s)", result.Status, string(body))
	}
	return nil
}
