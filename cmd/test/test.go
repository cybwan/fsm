package main

import (
	"fmt"
	"time"

	"github.com/flomesh-io/fsm/pkg/zookeeper"
	"github.com/flomesh-io/fsm/pkg/zookeeper/discovery"
	"github.com/flomesh-io/fsm/pkg/zookeeper/discovery/nebula"
)

func main() {
	client, err := zookeeper.NewClient(
		"zookeeperMetadataReport",
		[]string{"127.0.0.1:2181"},
		true,
		zookeeper.WithZkTimeOut(time.Second*15),
	)
	if err != nil {
		panic(err)
	}
	basePath := "/Application/grpc"
	sd := discovery.NewServiceDiscovery(client, basePath, new(nebula.Ops))
	fmt.Println(sd.QueryForNames())
	serviceInstances, err := sd.QueryForInstances("com.orientsec.demo.Greeter/providers")
	fmt.Println(serviceInstances)
	fmt.Println(err)
}
