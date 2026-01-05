package protocol

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketConn abstracts WebSocket operations for testing
type WebSocketConn interface {
	ReadJSON(v interface{}) error
	WriteJSON(v interface{}) error
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	Close() error
	SetWriteDeadline(t time.Time) error
}

// WebSocketDialer abstracts WebSocket dialing for testing
type WebSocketDialer interface {
	Dial(url string, headers http.Header) (WebSocketConn, *http.Response, error)
}

// DefaultWebSocketDialer wraps gorilla/websocket DefaultDialer
type DefaultWebSocketDialer struct{}

// Dial connects to a WebSocket server
func (d *DefaultWebSocketDialer) Dial(url string, headers http.Header) (WebSocketConn, *http.Response, error) {
	conn, resp, err := websocket.DefaultDialer.Dial(url, headers)
	if err != nil {
		return nil, resp, err
	}
	return &GorillaWebSocketConn{Conn: conn}, resp, nil
}

// GorillaWebSocketConn wraps gorilla/websocket for the WebSocketConn interface
type GorillaWebSocketConn struct {
	*websocket.Conn
}

func (c *GorillaWebSocketConn) ReadJSON(v interface{}) error {
	return c.Conn.ReadJSON(v)
}

func (c *GorillaWebSocketConn) WriteJSON(v interface{}) error {
	return c.Conn.WriteJSON(v)
}

func (c *GorillaWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	return c.Conn.ReadMessage()
}

func (c *GorillaWebSocketConn) WriteMessage(messageType int, data []byte) error {
	return c.Conn.WriteMessage(messageType, data)
}

func (c *GorillaWebSocketConn) Close() error {
	return c.Conn.Close()
}

func (c *GorillaWebSocketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
