// Package ctok implements a syncer from cloud to k8s.
package ctok

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff"

	"github.com/flomesh-io/fsm/pkg/connector"
	"github.com/flomesh-io/fsm/pkg/logger"
)

var (
	log = logger.New("connector-c2k")
)

// CtoKSource is the source for the sync that watches cloud services and
// updates a CtoKSyncer whenever the set of services to register changes.
type CtoKSource struct {
	controller connector.ConnectController
	syncer     *CtoKSyncer // syncer is the syncer to update with services
	discClient connector.ServiceDiscoveryClient

	domain string // DNS domain
}

func NewCtoKSource(controller connector.ConnectController,
	syncer *CtoKSyncer,
	discClient connector.ServiceDiscoveryClient,
	domain string) *CtoKSource {
	return &CtoKSource{
		controller: controller,
		syncer:     syncer,
		discClient: discClient,
		domain:     domain,
	}
}

// Run is the long-running loop for watching cloud services and
// updating the CtoKSyncer.
func (s *CtoKSource) Run(ctx context.Context) {
	opts := (&connector.QueryOptions{
		AllowStale: true,
		WaitIndex:  1,
		WaitTime:   s.controller.GetSyncPeriod(),
	}).WithContext(ctx)
	for {
		// Get all services.
		var catalogServices []connector.NamespacedService

		if !s.controller.Purge() {
			err := backoff.Retry(func() error {
				var err error
				catalogServices, err = s.discClient.CatalogServices(opts)
				return err
			}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx))

			// If the context is ended, then we end
			if ctx.Err() != nil {
				return
			}

			// If there was an error, handle that
			if err != nil {
				log.Warn().Msgf("error querying services, will retry, err:%s", err)
				continue
			}
		}

		var namespacedServices map[string]string
		var serviceConversions map[string]string
		enableConversions := s.controller.EnableC2KConversions()
		if enableConversions {
			namespacedServices = make(map[string]string, len(catalogServices))
			serviceConversions = s.controller.GetC2KServiceConversions()
		}

		services := make(map[connector.KubeSvcName]connector.CloudSvcName, len(catalogServices))

		for _, svc := range catalogServices {
			if enableConversions {
				namespacedServices[svc.Service] = svc.Namespace
				if len(serviceConversions) > 0 {
					if serviceConversion, exists := serviceConversions[fmt.Sprintf("%s/%s", svc.Namespace, svc.Service)]; exists {
						services[connector.KubeSvcName(serviceConversion)] = connector.CloudSvcName(svc.Service)
					}
				}
			} else {
				services[connector.KubeSvcName(svc.Service)] = connector.CloudSvcName(svc.Service)
			}
			services[connector.KubeSvcName(svc.Service)] = connector.CloudSvcName(svc.Service)
		}

		log.Trace().Msgf("received services from cloud, count:%d", len(services))

		s.syncer.SetServices(services, namespacedServices)

		time.Sleep(opts.WaitTime)
	}
}
