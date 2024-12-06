package zookeeper

import (
	"github.com/flomesh-io/fsm/pkg/logger"
)

var (
	log = logger.New("fsm-zookeeper")
)

const (
	ConfiguratorsCategory Category = "configurators"
	RouterCategory        Category = "category"
	ProviderCategory      Category = "providers"
	ConsumerCategory      Category = "consumers"
)

type Category string
