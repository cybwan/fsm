package main

import (
	"fmt"
	"time"

	"github.com/flomesh-io/fsm/pkg/zookeeper"
	"github.com/flomesh-io/fsm/pkg/zookeeper/discovery"
)

func main() {
	client, err := zookeeper.NewClient(
		"zookeeperMetadataReport",
		[]string{"127.0.0.1:2181"},
		true,
		zookeeper.WithZkTimeOut(time.Duration(time.Second*15)),
	)
	if err != nil {
		panic(err)
	}
	basePath := "/Application/grpc"
	sd := discovery.NewServiceDiscovery(client, basePath, nil, nil, nil, nil)
	fmt.Println(sd.QueryForNames())
	serviceInstances, err := sd.QueryForInstances("com.orientsec.demo.Greeter/providers")
	fmt.Println(serviceInstances)
	fmt.Println(err)
}
