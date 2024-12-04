package remoting

import (
	"fmt"
)

// DataListener defines common data listener interface
type DataListener interface {
	DataChange(event Event) bool // bool is return for interface implement is interesting
}

// EventType means SourceObjectEventType
type EventType int

const (
	// EventTypeAdd means add event
	EventTypeAdd EventType = iota
	// EventTypeDel means del event
	EventTypeDel
	EventTypeUpdate
)

var serviceEventTypeStrings = [...]string{
	"add",
	"delete",
	"update",
}

// nolint
func (t EventType) String() string {
	return serviceEventTypeStrings[t]
}

// Event defines common elements for service event
type Event struct {
	Path    string
	Action  EventType
	Content string
}

// nolint
func (e Event) String() string {
	return fmt.Sprintf("Event{Action{%s}, Content{%s}}", e.Action, e.Content)
}
