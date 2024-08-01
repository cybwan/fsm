package cli

import (
	"time"

	"github.com/flomesh-io/fsm/pkg/ztm"
)

func (c *client) OutboundListener(stopCh <-chan struct{}, mesh, endpoint string) {
	// Wait for one informer synchronization periods
	slidingTimer := time.NewTimer(time.Second * 10)
	defer slidingTimer.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-slidingTimer.C:
			newJob := func() *ztmOutboundJob {
				return &ztmOutboundJob{
					done:            make(chan struct{}),
					agentController: c,
					mesh:            mesh,
					endpoint:        endpoint,
				}
			}
			<-c.msgWorkQueues.AddJob(newJob())

			slidingTimer.Reset(time.Second * 10)
		}
	}
}

type ztmOutboundJob struct {
	// Optional waiter
	done            chan struct{}
	agentController ztm.AgentController

	mesh     string
	endpoint string
}

// GetDoneCh returns the channel, which when closed, indicates the job has been finished.
func (job *ztmOutboundJob) GetDoneCh() <-chan struct{} {
	return job.done
}

// Run is the logic unit of job
func (job *ztmOutboundJob) Run() {
	defer close(job.done)
	c := job.agentController
	c.SyncOutbound(job.mesh, job.endpoint)
}

// JobName implementation for this job, for logging purposes
func (job *ztmOutboundJob) JobName() string {
	return "fsm-ztm-outbound-job"
}
