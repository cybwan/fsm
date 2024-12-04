package main

import (
	"fmt"
	"time"

	"github.com/flomesh-io/fsm/pkg/zookeeper/discovery"
	"github.com/flomesh-io/fsm/pkg/zookeeper/zk/kv"
)

func main() {
	client, err := kv.NewZookeeperClient(
		"zookeeperMetadataReport",
		[]string{"127.0.0.1:2181"},
		true,
		kv.WithZkTimeOut(time.Duration(time.Second*15)),
	)
	if err != nil {
		panic(err)
	}
	basePath := "/Application/grpc"
	sd := discovery.NewServiceDiscovery(client, basePath)
	fmt.Println(sd.QueryForNames())
	serviceInstances, err := sd.QueryForInstances("com.orientsec.demo.Greeter/providers")
	fmt.Println(serviceInstances)
	fmt.Println(err)
}
