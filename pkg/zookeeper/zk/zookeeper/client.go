package zookeeper

import (
	"strings"

	"dubbo.apache.org/dubbo-go/v3/common/constant"
	"github.com/dubbogo/gost/log/logger"
	perrors "github.com/pkg/errors"

	"github.com/flomesh-io/fsm/pkg/zookeeper/zk/kv"
)

const (
	ConnDelay    = 3 // connection delay interval
	MaxFailTimes = 3 // max fail times
)

// ValidateZookeeperClient validates client and sets options
func ValidateZookeeperClient(container ZkClientFacade, zkName string) error {
	lock := container.ZkClientLock()
	url := container.GetURL()

	lock.Lock()
	defer lock.Unlock()

	if container.ZkClient() == nil {
		// in dubbo, every registry only connect one node, so this is []string{r.Address}
		timeout := url.GetParamDuration(constant.ConfigTimeoutKey, constant.DefaultRegTimeout)

		zkAddresses := strings.Split(url.Location, ",")
		logger.Infof("[Zookeeper Client] New zookeeper client with name = %s, zkAddress = %s, timeout = %s", zkName, url.Location, timeout.String())
		newClient, cltErr := kv.NewZookeeperClient(zkName, zkAddresses, true, kv.WithZkTimeOut(timeout))
		if cltErr != nil {
			logger.Warnf("newZookeeperClient(name{%s}, zk address{%v}, timeout{%d}) = error{%v}",
				zkName, url.Location, timeout.String(), cltErr)
			return perrors.WithMessagef(cltErr, "newZookeeperClient(address:%+v)", url.Location)
		}
		container.SetZkClient(newClient)
	}
	return nil
}
