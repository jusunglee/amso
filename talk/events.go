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

// EventHandlers holds callbacks for each event type.
type EventHandlers struct {
	OnMessage       func(MessageEvent)
	OnKick          func(KickEvent)
	OnDisconnect    func(DisconnectEvent)
	OnChannelJoin   func(ChannelJoinEvent)
	OnChannelLeave  func(ChannelLeaveEvent)
	OnRaw           func(method string, body []byte) // catch-all for unhandled push types
}
