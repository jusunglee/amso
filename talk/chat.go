// Package talk provides a high-level KakaoTalk client built on the LOCO protocol.
package talk

import (
	"encoding/json"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
)

// ChatType constants for KakaoTalk message types.
const (
	ChatTypeFeed    = 0
	ChatTypeText    = 1
	ChatTypePhoto   = 2
	ChatTypeVideo   = 3
	ChatTypeContact = 4
	ChatTypeAudio   = 5
	ChatTypeDictaphone = 6
	ChatTypeEmoticon   = 12
	ChatTypeCoupon     = 13
	ChatTypeFile       = 18
	ChatTypeReply      = 26
	ChatTypeMultiPhoto = 27
	ChatTypeVoIP       = 51
	ChatTypeLiveTalk   = 52
	ChatTypeCustom     = 71
	ChatTypeSearch     = 72
	ChatTypeMoney      = 81
)

// Chatlog represents a single chat message in a KakaoTalk channel.
type Chatlog struct {
	LogID     int64    `bson:"logId"`
	ChatID    int64    `bson:"chatId"`
	Type      int      `bson:"type"`
	Text      string   `bson:"message,omitempty"`
	SenderID  int64    `bson:"authorId"`
	SendAt    int64    `bson:"sendAt"`
	MessageID int64    `bson:"msgId"`
	PrevLogID int64    `bson:"prevId,omitempty"`
	Attachment bson.Raw `bson:"attachment,omitempty"`
}

// ParseChatlog parses a Chatlog from raw BSON.
func ParseChatlog(raw bson.Raw) (*Chatlog, error) {
	var c Chatlog
	if err := bson.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// PhotoAttachment represents attachment data for photo messages (type=2).
type PhotoAttachment struct {
	Path   string `json:"path"`
	URL    string `json:"url,omitempty"`
	Width  int    `json:"w"`
	Height int    `json:"h"`
	Size   int64  `json:"s"`
	Key    string `json:"k,omitempty"`
	Name   string `json:"name,omitempty"`
}

// FileAttachment represents attachment data for file messages (type=18).
type FileAttachment struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Size   int64  `json:"s"`
	Key    string `json:"k,omitempty"`
	Expire int64  `json:"expire,omitempty"`
}

// ParsePhotoAttachment parses a PhotoAttachment from a Chatlog's Attachment field.
// KakaoTalk stores attachments as JSON strings inside the BSON body.
func ParsePhotoAttachment(raw bson.Raw) (*PhotoAttachment, error) {
	var att PhotoAttachment
	// Try JSON string first (common encoding)
	if err := json.Unmarshal([]byte(raw), &att); err == nil && att.Path != "" {
		return &att, nil
	}
	// Fall back to BSON document
	if err := bson.Unmarshal(raw, &att); err != nil {
		return nil, fmt.Errorf("talk: parse photo attachment: %w", err)
	}
	return &att, nil
}

// ParseFileAttachment parses a FileAttachment from a Chatlog's Attachment field.
func ParseFileAttachment(raw bson.Raw) (*FileAttachment, error) {
	var att FileAttachment
	if err := json.Unmarshal([]byte(raw), &att); err == nil && att.Path != "" {
		return &att, nil
	}
	if err := bson.Unmarshal(raw, &att); err != nil {
		return nil, fmt.Errorf("talk: parse file attachment: %w", err)
	}
	return &att, nil
}
