package talk

import (
	"fmt"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/jusunglee/amso/loco"
)

// ChannelType constants.
const (
	ChannelTypeNormal = "OM"
	ChannelTypeOpen   = "OD"
	ChannelTypeMemoChat = "MemoChat"
)

// ChannelInfo represents a KakaoTalk chat channel.
type ChannelInfo struct {
	ID          int64  `bson:"chatId"`
	Type        string `bson:"type"`
	MemberCount int    `bson:"activeMembersCount"`
	NewMsgCount int    `bson:"newMessageCount"`
	LastLogID   int64  `bson:"lastLogId"`
	LastSeenLogID int64 `bson:"lastSeenLogId"`
	Raw         bson.Raw
}

// ChannelMember represents a member in a channel.
type ChannelMember struct {
	UserID    int64  `bson:"userId"`
	Nickname  string `bson:"nickName"`
	ProfileURL string `bson:"profileImageUrl"`
}

// parseChannelDatas parses raw BSON channel data (from LOGINLIST chatDatas or LCHATLIST).
func parseChannelDatas(raws []bson.Raw) ([]ChannelInfo, error) {
	channels := make([]ChannelInfo, 0, len(raws))
	for _, raw := range raws {
		// chatDatas entries have a "c" field (channelId) and a "t" field (type).
		var entry struct {
			ChannelID   int64  `bson:"c"`
			Type        string `bson:"t"`
			MemberCount int    `bson:"a"`
			NewMsgCount int    `bson:"n"`
			LastLogID   int64  `bson:"ll"`
		}
		if err := bson.Unmarshal(raw, &entry); err != nil {
			continue
		}
		channels = append(channels, ChannelInfo{
			ID:          entry.ChannelID,
			Type:        entry.Type,
			MemberCount: entry.MemberCount,
			NewMsgCount: entry.NewMsgCount,
			LastLogID:   entry.LastLogID,
			Raw:         raw,
		})
	}
	return channels, nil
}

// ListChannels retrieves the channel list via the LCHATLIST command.
func ListChannels(session *loco.Session, lastTokenID int64, maxCount int) ([]ChannelInfo, error) {
	if maxCount <= 0 {
		maxCount = 100
	}

	resp, err := session.Request("LCHATLIST", bson.M{
		"lastTokenId": lastTokenID,
		"cnt":         maxCount,
	})
	if err != nil {
		return nil, fmt.Errorf("talk: LCHATLIST: %w", err)
	}

	var parsed struct {
		ChatDatas []bson.Raw `bson:"chatDatas"`
	}
	if err := bson.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("talk: parse LCHATLIST: %w", err)
	}

	channels := make([]ChannelInfo, 0, len(parsed.ChatDatas))
	for _, raw := range parsed.ChatDatas {
		var ch ChannelInfo
		if err := bson.Unmarshal(raw, &ch); err != nil {
			continue
		}
		ch.Raw = raw
		channels = append(channels, ch)
	}

	return channels, nil
}

// GetChannelInfo retrieves detailed info for a single channel via CHATINFO.
func GetChannelInfo(session *loco.Session, channelID int64) (*ChannelInfo, error) {
	resp, err := session.Request("CHATINFO", bson.M{
		"chatId": channelID,
	})
	if err != nil {
		return nil, fmt.Errorf("talk: CHATINFO: %w", err)
	}

	var ch ChannelInfo
	if err := bson.Unmarshal(resp.Body, &ch); err != nil {
		return nil, fmt.Errorf("talk: parse CHATINFO: %w", err)
	}
	ch.Raw = resp.Body
	return &ch, nil
}

// GetChannelMembers retrieves the member list for a channel via GETMEM.
func GetChannelMembers(session *loco.Session, channelID int64) ([]ChannelMember, error) {
	resp, err := session.Request("GETMEM", bson.M{
		"chatId": channelID,
	})
	if err != nil {
		return nil, fmt.Errorf("talk: GETMEM: %w", err)
	}

	var parsed struct {
		Members []ChannelMember `bson:"members"`
	}
	if err := bson.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("talk: parse GETMEM: %w", err)
	}

	return parsed.Members, nil
}

// SyncMessages retrieves message history for a channel since a given logId via SYNCMSG.
func SyncMessages(session *loco.Session, channelID, sinceLogID int64, count int) ([]Chatlog, error) {
	if count <= 0 {
		count = 50
	}

	resp, err := session.Request("SYNCMSG", bson.M{
		"chatId": channelID,
		"cur":    sinceLogID,
		"cnt":    count,
		"max":    int64(0),
	})
	if err != nil {
		return nil, fmt.Errorf("talk: SYNCMSG: %w", err)
	}

	var parsed struct {
		Chatlogs []bson.Raw `bson:"chatLogs"`
	}
	if err := bson.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("talk: parse SYNCMSG: %w", err)
	}

	logs := make([]Chatlog, 0, len(parsed.Chatlogs))
	for _, raw := range parsed.Chatlogs {
		var cl Chatlog
		if err := bson.Unmarshal(raw, &cl); err != nil {
			continue
		}
		logs = append(logs, cl)
	}

	return logs, nil
}

// MarkRead marks messages as read in a channel via NOTIREAD.
func MarkRead(session *loco.Session, channelID, logID int64) error {
	_, err := session.Request("NOTIREAD", bson.M{
		"chatId":    channelID,
		"watermark": logID,
	})
	if err != nil {
		return fmt.Errorf("talk: NOTIREAD: %w", err)
	}
	return nil
}
