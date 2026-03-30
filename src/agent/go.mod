module gimlet/agent

go 1.25

require (
	gimlet/protocol v0.0.0
	github.com/gorilla/websocket v1.5.3
	github.com/rs/zerolog v1.35.0
)

replace gimlet/protocol => ../protocol

require (
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.29.0 // indirect
)
