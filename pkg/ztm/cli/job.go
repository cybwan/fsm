package cli

import (
	"github.com/flomesh-io/fsm/pkg/ztm"
)

// agentControllerJob is the job to generate pipy policy json
type agentControllerJob struct {
	// Optional waiter
	done            chan struct{}
	agentController ztm.AgentController
}

// GetDoneCh returns the channel, which when closed, indicates the job has been finished.
func (job *agentControllerJob) GetDoneCh() <-chan struct{} {
	return job.done
}

// Run is the logic unit of job
func (job *agentControllerJob) Run() {
	defer close(job.done)
	c := job.agentController
	c.Refresh()
}

// JobName implementation for this job, for logging purposes
func (job *agentControllerJob) JobName() string {
	return "fsm-ztm-agent-job"
}
