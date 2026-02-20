package talk

// Event is the base interface for all events dispatched by the client.
type Event interface {
	EventType() string
}

// MessageEvent is fired when a new chat message is received.
type MessageEvent struct {
	ChannelID int64
	Log       Chatlog
}

func (MessageEvent) EventType() string { return "MSG" }

// KickEvent is fired when the server kicks this client.
type KickEvent struct {
	Reason int
}

func (KickEvent) EventType() string { return "KICKOUT" }

// DisconnectEvent is fired when the connection is lost.
type DisconnectEvent struct {
	Err error
}

func (DisconnectEvent) EventType() string { return "DISCONNECT" }

// ChannelJoinEvent is fired when a user joins a channel.
type ChannelJoinEvent struct {
	ChannelID int64
	UserID    int64
}

func (ChannelJoinEvent) EventType() string { return "NEWMEM" }

// ChannelLeaveEvent is fired when a user leaves a channel.
type ChannelLeaveEvent struct {
	ChannelID int64
	UserID    int64
}

func (ChannelLeaveEvent) EventType() string { return "DELMEM" }

// ReadReceiptEvent is fired when someone reads messages in a channel.
type ReadReceiptEvent struct {
	ChannelID int64
	UserID    int64
	Watermark int64 // logId up to which messages have been read
}

func (ReadReceiptEvent) EventType() string { return "NOTIREAD" }

// TypingEvent is fired when someone starts typing in a channel.
type TypingEvent struct {
	ChannelID int64
	UserID    int64
}

func (TypingEvent) EventType() string { return "TYPING" }

// MessageDeleteEvent is fired when a message is deleted in a channel.
type MessageDeleteEvent struct {
	ChannelID int64
	LogID     int64
}

func (MessageDeleteEvent) EventType() string { return "DELETEMSG" }

// EventHandlers holds callbacks for each event type.
type EventHandlers struct {
	OnMessage       func(MessageEvent)
	OnKick          func(KickEvent)
	OnDisconnect    func(DisconnectEvent)
	OnChannelJoin   func(ChannelJoinEvent)
	OnChannelLeave  func(ChannelLeaveEvent)
	OnReadReceipt   func(ReadReceiptEvent)
	OnTyping        func(TypingEvent)
	OnMessageDelete func(MessageDeleteEvent)
	OnRaw           func(method string, body []byte) // catch-all for unhandled push types
}
