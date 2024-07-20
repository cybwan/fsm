package cli

import (
	"time"

	"github.com/flomesh-io/fsm/pkg/announcements"
)

// BroadcastListener listens for broadcast messages from the message broker
func (c *client) BroadcastListener(stopCh <-chan struct{}) {
	agentUpdatePubSub := c.msgBroker.GetZtmUpdatePubSub()
	agentUpdateChan := agentUpdatePubSub.Sub(announcements.ZtmAgentUpdate.String())
	defer c.msgBroker.Unsub(agentUpdatePubSub, agentUpdateChan)

	// Wait for one informer synchronization periods
	slidingTimer := time.NewTimer(time.Second * 10)
	defer slidingTimer.Stop()

	reconfirm := true

	for {
		select {
		case <-stopCh:
			return
		case <-agentUpdateChan:
			// Wait for an informer synchronization period
			slidingTimer.Reset(time.Second * 5)
			// Avoid data omission
			reconfirm = true
		case <-slidingTimer.C:
			newJob := func() *agentControllerJob {
				return &agentControllerJob{
					done:            make(chan struct{}),
					agentController: c,
				}
			}
			<-c.msgWorkQueues.AddJob(newJob())

			if reconfirm {
				reconfirm = false
				slidingTimer.Reset(time.Second * 10)
			}
		}
	}
}
