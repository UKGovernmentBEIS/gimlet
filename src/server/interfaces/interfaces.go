package interfaces

import (
	"time"

	"gimlet/protocol"

	"github.com/gorilla/websocket"
)

// WebSocketConn is re-exported from protocol for backward compatibility
type WebSocketConn = protocol.WebSocketConn

// RealWebSocketConn wraps gorilla websocket for production use
type RealWebSocketConn struct {
	*websocket.Conn
}

func (c *RealWebSocketConn) ReadJSON(v interface{}) error {
	return c.Conn.ReadJSON(v)
}

func (c *RealWebSocketConn) WriteJSON(v interface{}) error {
	return c.Conn.WriteJSON(v)
}

func (c *RealWebSocketConn) Close() error {
	return c.Conn.Close()
}

func (c *RealWebSocketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *RealWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	return c.Conn.ReadMessage()
}

func (c *RealWebSocketConn) WriteMessage(messageType int, data []byte) error {
	return c.Conn.WriteMessage(messageType, data)
}
