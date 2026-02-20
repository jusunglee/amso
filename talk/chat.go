// Package talk provides a high-level KakaoTalk client built on the LOCO protocol.
package talk

import "go.mongodb.org/mongo-driver/bson"

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
