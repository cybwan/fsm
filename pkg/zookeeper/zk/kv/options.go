package kv

import (
	"time"

	"github.com/dubbogo/go-zookeeper/zk"
)

// nolint
type options struct {
	ZkName string
	Client *ZookeeperClient
	Ts     *zk.TestCluster
}

// Option will define a function of handling Options
type Option func(*options)

// WithZkName sets zk Client name
func WithZkName(name string) Option {
	return func(opt *options) {
		opt.ZkName = name
	}
}

type zkClientOption func(*ZookeeperClient)

// WithZkEventHandler sets zk Client event
func WithZkEventHandler(handler ZkEventHandler) zkClientOption {
	return func(opt *ZookeeperClient) {
		opt.zkEventHandler = handler
	}
}

// WithZkTimeOut sets zk Client timeout
func WithZkTimeOut(t time.Duration) zkClientOption {
	return func(opt *ZookeeperClient) {
		opt.Timeout = t
	}
}
