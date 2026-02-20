package talk

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/jusunglee/amso/auth"
	"github.com/jusunglee/amso/loco"
	"github.com/jusunglee/amso/network"
)

// Client is the high-level KakaoTalk client. It manages authentication,
// the LOCO session, event dispatch, and channel operations.
type Client struct {
	Config *network.Config

	AccessToken  string
	RefreshToken string
	UserID       int64
	DeviceUUID   string

	session       *loco.Session
	loginChannels []bson.Raw // raw channel data from LOGINLIST
	Handlers      EventHandlers

	// Stored credentials for re-login (populated by Login(), empty if LoginWithToken()).
	email    string
	password string

	mu     sync.RWMutex
	closed bool
}

// NewClient creates a new Client with default config.
func NewClient() *Client {
	return &Client{
		Config: network.DefaultConfig(),
	}
}

// LoginOptions controls login behavior.
type LoginOptions struct {
	// Forced forces login even if another session exists.
	// WARNING: each forced login consumes the device registration,
	// requiring the full passcode re-confirmation flow.
	Forced bool
}

// Login performs the full authentication flow: HTTP login → booking → checkin → LOGINLIST.
// Uses Forced: false by default to avoid burning the device registration.
func (c *Client) Login(email, password, deviceUUID, deviceName string) error {
	return c.LoginWithOptions(email, password, deviceUUID, deviceName, LoginOptions{Forced: false})
}

// LoginWithOptions performs the full authentication flow with configurable options.
func (c *Client) LoginWithOptions(email, password, deviceUUID, deviceName string, opts LoginOptions) error {
	loginResp, err := auth.Login(auth.LoginRequest{
		Email:      email,
		Password:   password,
		DeviceUUID: deviceUUID,
		DeviceName: deviceName,
		Agent:      c.Config.Agent,
		Forced:     opts.Forced,
	})
	if err != nil {
		return fmt.Errorf("talk: login: %w", err)
	}

	c.AccessToken = loginResp.AccessToken
	c.RefreshToken = loginResp.RefreshToken
	c.UserID = loginResp.UserID
	c.DeviceUUID = deviceUUID
	c.email = email
	c.password = password

	return c.connect()
}

// LoginWithToken connects using a previously obtained access token.
func (c *Client) LoginWithToken(accessToken string, userID int64, deviceUUID string) error {
	c.AccessToken = accessToken
	c.UserID = userID
	c.DeviceUUID = deviceUUID
	return c.connect()
}

func (c *Client) connect() error {
	session, loginResult, err := network.Connect(c.AccessToken, c.UserID, c.DeviceUUID, c.Config)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.session = session
	c.closed = false
	c.mu.Unlock()

	session.OnPush = c.handlePush

	// Parse channels from LOGINLIST response.
	if loginResult != nil {
		c.mu.Lock()
		c.loginChannels = loginResult.Channels
		c.mu.Unlock()
	}
	return nil
}

// Reconnect tears down the current session and establishes a new one.
func (c *Client) Reconnect() error {
	c.mu.Lock()
	if c.session != nil {
		c.session.Close()
	}
	c.mu.Unlock()

	// Brief pause before reconnecting.
	time.Sleep(1 * time.Second)
	return c.connect()
}

// Session returns the underlying LOCO session for direct protocol access.
func (c *Client) Session() *loco.Session {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session
}

// bodyStatus extracts the status field from a LOCO response BSON body.
// LOCO uses the BSON body status (int32), not the packet header StatusCode (uint16).
func bodyStatus(body bson.Raw) int32 {
	var s struct {
		Status int32 `bson:"status"`
	}
	bson.Unmarshal(body, &s)
	return s.Status
}

// SendText sends a text message to a channel.
func (c *Client) SendText(channelID int64, text string) (*Chatlog, error) {
	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}

	resp, err := session.Request("WRITE", bson.M{
		"chatId": channelID,
		"type":   ChatTypeText,
		"msg":    text,
		"noSeen": true,
		"msgId":  time.Now().UnixMilli(),
	})
	if err != nil {
		return nil, fmt.Errorf("talk: WRITE: %w", err)
	}

	if s := bodyStatus(resp.Body); s != 0 {
		return nil, fmt.Errorf("talk: WRITE failed with status %d", s)
	}

	var cl Chatlog
	if err := bson.Unmarshal(resp.Body, &cl); err != nil {
		return nil, fmt.Errorf("talk: parse WRITE response: %w", err)
	}

	return &cl, nil
}

// SendReply sends a reply to a specific message in a channel.
func (c *Client) SendReply(channelID int64, text string, replyToLogID int64) (*Chatlog, error) {
	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}

	attachmentData, err := bson.Marshal(bson.M{
		"src_logId": replyToLogID,
	})
	if err != nil {
		return nil, fmt.Errorf("talk: marshal reply attachment: %w", err)
	}

	resp, err := session.Request("WRITE", bson.M{
		"chatId":    channelID,
		"type":      ChatTypeReply,
		"msg":       text,
		"noSeen":    true,
		"msgId":     time.Now().UnixMilli(),
		"extra":     string(attachmentData),
	})
	if err != nil {
		return nil, fmt.Errorf("talk: WRITE reply: %w", err)
	}

	if s := bodyStatus(resp.Body); s != 0 {
		return nil, fmt.Errorf("talk: WRITE reply failed with status %d", s)
	}

	var cl Chatlog
	if err := bson.Unmarshal(resp.Body, &cl); err != nil {
		return nil, fmt.Errorf("talk: parse WRITE reply response: %w", err)
	}

	return &cl, nil
}

// ForwardMessage forwards a message to another channel.
func (c *Client) ForwardMessage(fromChannelID, toChannelID, logID int64) (*Chatlog, error) {
	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}

	resp, err := session.Request("FORWARD", bson.M{
		"chatId":    toChannelID,
		"srcChatId": fromChannelID,
		"srcLogId":  logID,
		"msgId":     time.Now().UnixMilli(),
	})
	if err != nil {
		return nil, fmt.Errorf("talk: FORWARD: %w", err)
	}

	if s := bodyStatus(resp.Body); s != 0 {
		return nil, fmt.Errorf("talk: FORWARD failed with status %d", s)
	}

	var cl Chatlog
	if err := bson.Unmarshal(resp.Body, &cl); err != nil {
		return nil, fmt.Errorf("talk: parse FORWARD response: %w", err)
	}

	return &cl, nil
}

// DeleteMessage deletes a message from a channel via DELETEMSG.
func (c *Client) DeleteMessage(channelID, logID int64) error {
	session := c.Session()
	if session == nil {
		return fmt.Errorf("talk: not connected")
	}

	resp, err := session.Request("DELETEMSG", bson.M{
		"chatId": channelID,
		"logId":  logID,
	})
	if err != nil {
		return fmt.Errorf("talk: DELETEMSG: %w", err)
	}
	if s := bodyStatus(resp.Body); s != 0 {
		return fmt.Errorf("talk: DELETEMSG failed with status %d", s)
	}
	return nil
}

// ListChannels returns the channel list, using the LOGINLIST data if available.
func (c *Client) ListChannels() ([]ChannelInfo, error) {
	c.mu.RLock()
	raw := c.loginChannels
	c.mu.RUnlock()

	if len(raw) > 0 {
		return parseChannelDatas(raw)
	}

	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}
	return ListChannels(session, 0, 100)
}

// GetChannelInfo returns info for a specific channel.
func (c *Client) GetChannelInfo(channelID int64) (*ChannelInfo, error) {
	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}
	return GetChannelInfo(session, channelID)
}

// GetChannelMembers returns the members of a channel.
func (c *Client) GetChannelMembers(channelID int64) ([]ChannelMember, error) {
	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}
	return GetChannelMembers(session, channelID)
}

// GetMember returns a specific member from a channel by user ID.
func (c *Client) GetMember(channelID int64, userID int64) (*ChannelMember, error) {
	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}
	return GetMember(session, channelID, userID)
}

// SyncMessages retrieves message history.
func (c *Client) SyncMessages(channelID, sinceLogID int64, count int) ([]Chatlog, error) {
	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}
	return SyncMessages(session, channelID, sinceLogID, count)
}

// MarkRead marks messages as read in a channel.
func (c *Client) MarkRead(channelID, logID int64) error {
	session := c.Session()
	if session == nil {
		return fmt.Errorf("talk: not connected")
	}
	return MarkRead(session, channelID, logID)
}

// SendPhoto uploads a photo and sends it as a photo message to a channel.
func (c *Client) SendPhoto(channelID int64, filename string, data io.Reader, width, height int) (*Chatlog, error) {
	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}

	result, err := UploadImage(c.AccessToken, c.UserID, filename, data)
	if err != nil {
		return nil, fmt.Errorf("talk: upload photo: %w", err)
	}

	extra, err := json.Marshal(map[string]interface{}{
		"path": result.Path,
		"w":    width,
		"h":    height,
		"s":    result.Size,
		"name": filename,
	})
	if err != nil {
		return nil, fmt.Errorf("talk: marshal photo extra: %w", err)
	}

	resp, err := session.Request("WRITE", bson.M{
		"chatId": channelID,
		"type":   ChatTypePhoto,
		"msg":    "",
		"extra":  string(extra),
		"noSeen": true,
		"msgId":  time.Now().UnixMilli(),
	})
	if err != nil {
		return nil, fmt.Errorf("talk: WRITE photo: %w", err)
	}
	if s := bodyStatus(resp.Body); s != 0 {
		return nil, fmt.Errorf("talk: WRITE photo failed with status %d", s)
	}

	var cl Chatlog
	if err := bson.Unmarshal(resp.Body, &cl); err != nil {
		return nil, fmt.Errorf("talk: parse WRITE photo response: %w", err)
	}
	return &cl, nil
}

// SendFile uploads a file and sends it as a file message to a channel.
func (c *Client) SendFile(channelID int64, filename string, data io.Reader, size int64) (*Chatlog, error) {
	session := c.Session()
	if session == nil {
		return nil, fmt.Errorf("talk: not connected")
	}

	result, err := UploadFile(c.AccessToken, c.UserID, filename, data)
	if err != nil {
		return nil, fmt.Errorf("talk: upload file: %w", err)
	}

	extra, err := json.Marshal(map[string]interface{}{
		"path": result.Path,
		"name": filename,
		"s":    size,
	})
	if err != nil {
		return nil, fmt.Errorf("talk: marshal file extra: %w", err)
	}

	resp, err := session.Request("WRITE", bson.M{
		"chatId": channelID,
		"type":   ChatTypeFile,
		"msg":    "",
		"extra":  string(extra),
		"noSeen": true,
		"msgId":  time.Now().UnixMilli(),
	})
	if err != nil {
		return nil, fmt.Errorf("talk: WRITE file: %w", err)
	}
	if s := bodyStatus(resp.Body); s != 0 {
		return nil, fmt.Errorf("talk: WRITE file failed with status %d", s)
	}

	var cl Chatlog
	if err := bson.Unmarshal(resp.Body, &cl); err != nil {
		return nil, fmt.Errorf("talk: parse WRITE file response: %w", err)
	}
	return &cl, nil
}

// RefreshSession attempts to refresh the access token and reconnect.
// Falls back to full re-login if token refresh fails.
func (c *Client) RefreshSession() error {
	if c.RefreshToken != "" {
		ac := auth.NewAuthClient(c.email, c.password, c.DeviceUUID, "amso-client")
		resp, err := ac.RefreshToken(c.RefreshToken)
		if err == nil {
			c.AccessToken = resp.AccessToken
			if resp.RefreshToken != "" {
				c.RefreshToken = resp.RefreshToken
			}
			return c.Reconnect()
		}
		log.Printf("talk: token refresh failed, attempting full re-login: %v", err)
	}

	if c.email != "" && c.password != "" {
		return c.LoginWithOptions(c.email, c.password, c.DeviceUUID, "amso-client", LoginOptions{Forced: false})
	}

	return fmt.Errorf("talk: cannot refresh session: no refresh token or credentials available")
}

// Close shuts down the client and its LOCO session.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	if c.session != nil {
		return c.session.Close()
	}
	return nil
}

func (c *Client) handlePush(p *loco.Packet) {
	switch p.Method {
	case "MSG":
		c.handleMessage(p)
	case "NEWMEM":
		c.handleNewMember(p)
	case "DELMEM":
		c.handleDelMember(p)
	case "KICKOUT":
		c.handleKickout(p)
	case "CHANGESVR":
		go func() {
			log.Printf("talk: server change requested, reconnecting...")
			if err := c.Reconnect(); err != nil {
				log.Printf("talk: reconnect after CHANGESVR failed: %v", err)
				if c.Handlers.OnDisconnect != nil {
					c.Handlers.OnDisconnect(DisconnectEvent{Err: err})
				}
			}
		}()
	case "NOTIREAD", "DECUNREAD":
		c.handleReadReceipt(p)
	case "SETMST":
		c.handleTyping(p)
	case "DELETEMSG":
		c.handleDeleteMessage(p)
	default:
		if c.Handlers.OnRaw != nil {
			c.Handlers.OnRaw(p.Method, p.Body)
		}
	}
}

func (c *Client) handleMessage(p *loco.Packet) {
	if c.Handlers.OnMessage == nil {
		return
	}

	var data struct {
		ChatLog bson.Raw `bson:"chatLog"`
		ChatID  int64    `bson:"chatId"`
	}
	if err := bson.Unmarshal(p.Body, &data); err != nil {
		log.Printf("talk: failed to parse MSG push: %v", err)
		return
	}

	var cl Chatlog
	if err := bson.Unmarshal(data.ChatLog, &cl); err != nil {
		log.Printf("talk: failed to parse chatlog in MSG: %v", err)
		return
	}

	if cl.ChatID == 0 {
		cl.ChatID = data.ChatID
	}

	c.Handlers.OnMessage(MessageEvent{
		ChannelID: cl.ChatID,
		Log:       cl,
	})
}

func (c *Client) handleNewMember(p *loco.Packet) {
	if c.Handlers.OnChannelJoin == nil {
		return
	}

	var data struct {
		ChatID int64 `bson:"chatId"`
		UserID int64 `bson:"authorId"`
	}
	if err := bson.Unmarshal(p.Body, &data); err != nil {
		log.Printf("talk: failed to parse NEWMEM push: %v", err)
		return
	}

	c.Handlers.OnChannelJoin(ChannelJoinEvent{
		ChannelID: data.ChatID,
		UserID:    data.UserID,
	})
}

func (c *Client) handleDelMember(p *loco.Packet) {
	if c.Handlers.OnChannelLeave == nil {
		return
	}

	var data struct {
		ChatID int64 `bson:"chatId"`
		UserID int64 `bson:"authorId"`
	}
	if err := bson.Unmarshal(p.Body, &data); err != nil {
		log.Printf("talk: failed to parse DELMEM push: %v", err)
		return
	}

	c.Handlers.OnChannelLeave(ChannelLeaveEvent{
		ChannelID: data.ChatID,
		UserID:    data.UserID,
	})
}

func (c *Client) handleKickout(p *loco.Packet) {
	var data struct {
		Reason int `bson:"reason"`
	}
	bson.Unmarshal(p.Body, &data)

	if c.Handlers.OnKick != nil {
		c.Handlers.OnKick(KickEvent{Reason: data.Reason})
	}
}

func (c *Client) handleReadReceipt(p *loco.Packet) {
	if c.Handlers.OnReadReceipt == nil {
		return
	}

	var data struct {
		ChatID    int64 `bson:"chatId"`
		UserID    int64 `bson:"userId"`
		Watermark int64 `bson:"watermark"`
	}
	if err := bson.Unmarshal(p.Body, &data); err != nil {
		log.Printf("talk: failed to parse %s push: %v", p.Method, err)
		return
	}

	c.Handlers.OnReadReceipt(ReadReceiptEvent{
		ChannelID: data.ChatID,
		UserID:    data.UserID,
		Watermark: data.Watermark,
	})
}

func (c *Client) handleTyping(p *loco.Packet) {
	if c.Handlers.OnTyping == nil {
		return
	}

	var data struct {
		ChatID int64 `bson:"chatId"`
		UserID int64 `bson:"authorId"`
	}
	if err := bson.Unmarshal(p.Body, &data); err != nil {
		log.Printf("talk: failed to parse typing push: %v", err)
		return
	}

	c.Handlers.OnTyping(TypingEvent{
		ChannelID: data.ChatID,
		UserID:    data.UserID,
	})
}

func (c *Client) handleDeleteMessage(p *loco.Packet) {
	if c.Handlers.OnMessageDelete == nil {
		return
	}

	var data struct {
		ChatID int64 `bson:"chatId"`
		LogID  int64 `bson:"logId"`
	}
	if err := bson.Unmarshal(p.Body, &data); err != nil {
		log.Printf("talk: failed to parse DELETEMSG push: %v", err)
		return
	}

	c.Handlers.OnMessageDelete(MessageDeleteEvent{
		ChannelID: data.ChatID,
		LogID:     data.LogID,
	})
}

// SendTyping sends a typing indicator to a channel (fire-and-forget).
func (c *Client) SendTyping(channelID int64) error {
	session := c.Session()
	if session == nil {
		return fmt.Errorf("talk: not connected")
	}
	return session.Send("SETMST", bson.M{
		"chatId": channelID,
		"t":      1,
	})
}
