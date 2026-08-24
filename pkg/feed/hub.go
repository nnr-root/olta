package feed

import "github.com/gorilla/websocket"

type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

// Hub maintains subscribers and a bounded in-memory replay history.
type Hub struct {
	clients      map[*Client]bool
	broadcast    chan []byte
	register     chan *Client
	unregister   chan *Client
	history      [][]byte
	historyLimit int
}

func newHub(historyLimit int) *Hub {
	return &Hub{
		broadcast:    make(chan []byte),
		register:     make(chan *Client),
		unregister:   make(chan *Client),
		clients:      make(map[*Client]bool),
		historyLimit: historyLimit,
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			for _, message := range h.history {
				client.send <- append([]byte(nil), message...)
			}
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.broadcast:
			if h.historyLimit > 0 {
				h.history = append(h.history, append([]byte(nil), message...))
				if len(h.history) > h.historyLimit {
					copy(h.history, h.history[len(h.history)-h.historyLimit:])
					h.history = h.history[:h.historyLimit]
				}
			}
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}
