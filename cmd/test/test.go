package main

import (
	"encoding/json"
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
	category := "providers"
	sd := discovery.NewServiceDiscovery(client, basePath, category, new(nebula.Ops))
	fmt.Println(sd.QueryForNames())
	if serviceInstances, err := sd.QueryForInstances("com.orientsec.demo.Greeter"); err == nil {
		for _, serviceInstance := range serviceInstances {
			bytes, _ := json.MarshalIndent(serviceInstance, "", " ")
			fmt.Println(string(bytes))
		}
	} else {
		fmt.Println(err.Error())
	}
}
