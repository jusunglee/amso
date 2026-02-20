package talk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
)

const (
	uploadHost   = "up-p.talk.kakao.com"
	downloadHost = "dn-p.talk.kakao.com"
)

// UploadResult contains the server response after a successful media upload.
type UploadResult struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// UploadImage uploads an image file to KakaoTalk's media server.
func UploadImage(accessToken string, userID int64, filename string, data io.Reader) (*UploadResult, error) {
	return upload(accessToken, userID, "image", filename, data)
}

// UploadFile uploads a generic file to KakaoTalk's media server.
func UploadFile(accessToken string, userID int64, filename string, data io.Reader) (*UploadResult, error) {
	return upload(accessToken, userID, "file", filename, data)
}

func upload(accessToken string, userID int64, attachmentType, filename string, data io.Reader) (*UploadResult, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	w.WriteField("user_id", fmt.Sprintf("%d", userID))
	w.WriteField("attachment_type", attachmentType)

	part, err := w.CreateFormFile("attachment", filename)
	if err != nil {
		return nil, fmt.Errorf("talk: create form file: %w", err)
	}
	if _, err := io.Copy(part, data); err != nil {
		return nil, fmt.Errorf("talk: copy file data: %w", err)
	}
	w.Close()

	url := fmt.Sprintf("https://%s/upload", uploadHost)
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return nil, fmt.Errorf("talk: create upload request: %w", err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", accessToken)
	req.Header.Set("A", "mac/26.1.4/ko")
	req.Header.Set("User-Agent", "KT/26.1.4 Mc/26.2 ko")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("talk: upload request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("talk: read upload response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("talk: upload failed HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result UploadResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("talk: parse upload response: %w (body: %s)", err, string(body))
	}
	return &result, nil
}

// DownloadURL constructs the download URL for a media attachment given its path/key.
func DownloadURL(path string) string {
	return fmt.Sprintf("https://%s/%s", downloadHost, path)
}
