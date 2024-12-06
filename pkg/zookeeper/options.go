package zookeeper

import (
	"time"

	"github.com/dubbogo/go-zookeeper/zk"
)

// nolint
type options struct {
	ZkName string
	Client *Client
	Ts     *zk.TestCluster
}

// Option will define a function of handling Options
type Option func(*options)

type zkClientOption func(*Client)

// WithZkTimeOut sets zk Client timeout
func WithZkTimeOut(t time.Duration) zkClientOption {
	return func(opt *Client) {
		opt.timeout = t
	}
}
