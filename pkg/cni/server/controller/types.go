// Package cniserver implements FSM CNI Control Server.
package controller

import "github.com/flomesh-io/fsm/pkg/logger"

var (
	log = logger.New("interceptor-ctrl-server")
)

// Server CNI Server.
type Server interface {
	Start() error
	Stop()
}
