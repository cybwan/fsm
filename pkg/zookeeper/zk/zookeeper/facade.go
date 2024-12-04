package zookeeper

import (
	"sync"
	"time"

	"dubbo.apache.org/dubbo-go/v3/common"
	"github.com/dubbogo/gost/log/logger"

	"github.com/flomesh-io/fsm/pkg/zookeeper/zk/kv"
)

type ZkClientFacade interface {
	ZkClient() *kv.ZookeeperClient
	SetZkClient(*kv.ZookeeperClient)
	ZkClientLock() *sync.Mutex
	WaitGroup() *sync.WaitGroup // for wait group control, zk client listener & zk client container
	Done() chan struct{}        // for registry destroy
	RestartCallBack() bool
	GetURL() *common.URL
}

// HandleClientRestart keeps the connection between client and server
// This method should be used only once. You can use handleClientRestart() in package registry.
func HandleClientRestart(r ZkClientFacade) {
	defer r.WaitGroup().Done()
	for {
		select {
		case <-r.ZkClient().Reconnect():
			r.RestartCallBack()
			time.Sleep(10 * time.Microsecond)
		case <-r.Done():
			logger.Warnf("receive registry destroy event, quit client restart handler")
			return
		}
	}
}
