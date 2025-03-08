package ctok

import (
	"context"
	"fmt"
	"strings"
	"time"

	ctv1 "github.com/flomesh-io/fsm/pkg/apis/connector/v1alpha1"
	"github.com/flomesh-io/fsm/pkg/connector"
)

// Aggregate micro services
func (s *CtoKSource) Aggregate(ctx context.Context, k8sSvcName connector.MicroSvcName) map[connector.MicroSvcName]*connector.MicroSvcMeta {
	cloudSvcName, exists := s.syncer.controller.GetC2KContext().NativeServices[connector.KubeSvcName(k8sSvcName)]
	if !exists {
		return nil
	}

	opts := (&connector.QueryOptions{
		AllowStale: true,
		WaitIndex:  1,
		WaitTime:   5 * time.Second,
	}).WithContext(ctx)

	instanceEntries, err := s.discClient.CatalogInstances(string(cloudSvcName), opts)
	if err != nil {
		return nil
	}

	if len(instanceEntries) == 0 {
		return nil
	}

	svcMetaMap := make(map[connector.MicroSvcName]*connector.MicroSvcMeta)

	for _, instance := range instanceEntries {
		instance.MicroService.Service = strings.ToLower(instance.MicroService.Service)
		k8sSvcNames := []connector.MicroSvcName{connector.MicroSvcName(instance.MicroService.Service)}
		if len(instance.Tags) > 0 {
			k8sSvcNames = s.aggregateTag(k8sSvcName, instance, k8sSvcNames)
		}
		if len(instance.Meta) > 0 {
			k8sSvcNames = s.aggregateMetadata(k8sSvcName, instance, k8sSvcNames)
		}
		for _, serviceName := range k8sSvcNames {
			s.aggregateMeta(svcMetaMap, serviceName, instance)
		}
	}
	return svcMetaMap
}

func (s *CtoKSource) aggregateMeta(svcMetaMap map[connector.MicroSvcName]*connector.MicroSvcMeta, k8sSvcName connector.MicroSvcName, instance *connector.AgentService) {
	port := instance.MicroService.EndpointPort()
	protocol := instance.MicroService.Protocol()
	svcMeta, exists := svcMetaMap[k8sSvcName]
	if !exists {
		svcMeta = new(connector.MicroSvcMeta)
		svcMeta.TargetPorts = make(map[connector.MicroServicePort]connector.MicroServiceProtocol)
		svcMeta.Endpoints = make(map[connector.MicroServiceAddress]*connector.MicroEndpointMeta)
		svcMetaMap[k8sSvcName] = svcMeta
	}

	if len(instance.Ports) > 0 {
		svcMeta.Ports = make(map[connector.MicroServicePort]connector.MicroServicePort)
		for targetPort, port := range instance.Ports {
			svcMeta.Ports[targetPort] = port
		}
	}

	svcMeta.HealthCheck = instance.HealthCheck

	endpointMeta := new(connector.MicroEndpointMeta)
	endpointMeta.Ports = make(map[connector.MicroServicePort]connector.MicroServiceProtocol)
	if *port > 0 {
		svcMeta.TargetPorts[*port] = *protocol
		endpointMeta.Ports[*port] = *protocol
	}
	if *protocol == connector.ProtocolGRPC {
		if len(instance.GRPCInterface) > 0 && len(instance.GRPCMethods) > 0 {
			if svcMeta.GRPCMeta == nil {
				svcMeta.GRPCMeta = new(connector.GRPCMeta)
			}
			svcMeta.GRPCMeta.Interface = instance.GRPCInterface
			if svcMeta.GRPCMeta.Methods == nil {
				svcMeta.GRPCMeta.Methods = make(map[string][]string)
			}
			for _, method := range instance.GRPCMethods {
				eps, exists := svcMeta.GRPCMeta.Methods[method]
				if !exists {
					eps = make([]string, 0)
				}
				eps = append(eps, instance.MicroService.EndpointAddress().Get())
				svcMeta.GRPCMeta.Methods[method] = eps
			}
			endpointMeta.GRPCMeta = instance.Meta
		}
	}
	endpointMeta.Address = *instance.MicroService.EndpointAddress()
	endpointMeta.Native.ClusterId = instance.ClusterId
	endpointMeta.Native.ViaGatewayMode = ctv1.Forward
	if viaGatewayModeIf, ok := instance.Meta[connector.CloudViaGatewayMode]; ok {
		if viaGatewayMode, str := viaGatewayModeIf.(string); str {
			if len(viaGatewayMode) > 0 {
				endpointMeta.Native.ViaGatewayMode = ctv1.WithGatewayMode(viaGatewayMode)
			}
		}
	}
	if httpViaGatewayIf, ok := instance.Meta[connector.CloudHTTPViaGateway]; ok {
		if httpViaGateway, str := httpViaGatewayIf.(string); str {
			if len(httpViaGateway) > 0 {
				endpointMeta.Native.ViaGatewayHTTP = httpViaGateway
			}
		}
	}
	if grpcViaGatewayIf, ok := instance.Meta[connector.CloudGRPCViaGateway]; ok {
		if grpcViaGateway, str := grpcViaGatewayIf.(string); str {
			if len(grpcViaGateway) > 0 {
				endpointMeta.Native.ViaGatewayGRPC = grpcViaGateway
			}
		}
	}
	if clusterSetIf, ok := instance.Meta[connector.ClusterSetKey]; ok {
		if clusterSet, str := clusterSetIf.(string); str {
			if len(clusterSet) > 0 {
				endpointMeta.Native.ClusterSet = clusterSet
				endpointMeta.Native.ClusterId = clusterSet
			}
		}
	}
	if len(endpointMeta.Native.ClusterSet) == 0 || len(endpointMeta.Native.ClusterId) > 0 {
		endpointMeta.Native.ClusterSet = endpointMeta.Native.ClusterId
	}
	svcMeta.Endpoints[*instance.MicroService.EndpointAddress()] = endpointMeta
}

func (s *CtoKSource) aggregateTag(k8sSvcName connector.MicroSvcName, svc *connector.AgentService, k8sSvcNames []connector.MicroSvcName) []connector.MicroSvcName {
	svcPrefix := ""
	svcSuffix := ""
	for _, tag := range svc.Tags {
		if len(s.controller.GetPrefixTag()) > 0 {
			if strings.HasPrefix(tag, fmt.Sprintf("%s=", s.controller.GetPrefixTag())) {
				if segs := strings.Split(tag, "="); len(segs) == 2 {
					svcPrefix = segs[1]
				}
			}
		}
		if len(s.controller.GetSuffixTag()) > 0 {
			if strings.HasPrefix(tag, fmt.Sprintf("%s=", s.controller.GetSuffixTag())) {
				if segs := strings.Split(tag, "="); len(segs) == 2 {
					svcSuffix = segs[1]
				}
			}
		}
	}
	if len(svcPrefix) > 0 || len(svcSuffix) > 0 {
		extSvcName := string(k8sSvcName)
		if len(svcPrefix) > 0 {
			extSvcName = fmt.Sprintf("%s-%s", svcPrefix, extSvcName)
		}
		if len(svcSuffix) > 0 {
			extSvcName = fmt.Sprintf("%s-%s", extSvcName, svcSuffix)
		}
		k8sSvcNames = append(k8sSvcNames, connector.MicroSvcName(extSvcName))
	}
	return k8sSvcNames
}

func (s *CtoKSource) aggregateMetadata(k8sSvcName connector.MicroSvcName, svc *connector.AgentService, k8sSvcNames []connector.MicroSvcName) []connector.MicroSvcName {
	svcPrefix := ""
	svcSuffix := ""
	for metaName, metaVal := range svc.Meta {
		if len(s.controller.GetPrefixMetadata()) > 0 {
			if strings.EqualFold(metaName, s.controller.GetPrefixMetadata()) {
				if v, ok := metaVal.(string); ok {
					svcPrefix = v
				}
			}
		}
		if len(s.controller.GetSuffixMetadata()) > 0 {
			if strings.EqualFold(metaName, s.controller.GetSuffixMetadata()) {
				if v, ok := metaVal.(string); ok {
					svcSuffix = v
				}
			}
		}
	}
	if len(svcPrefix) > 0 || len(svcSuffix) > 0 {
		extSvcName := string(k8sSvcName)
		if len(svcPrefix) > 0 {
			extSvcName = fmt.Sprintf("%s-%s", svcPrefix, extSvcName)
		}
		if len(svcSuffix) > 0 {
			extSvcName = fmt.Sprintf("%s-%s", extSvcName, svcSuffix)
		}
		k8sSvcNames = append(k8sSvcNames, connector.MicroSvcName(extSvcName))
	}
	return k8sSvcNames
}
