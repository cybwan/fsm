package helpers

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
)

// LoadProgs load ebpf progs
func LoadProgs(useCniMode, kernelTracing bool) error {
	if os.Getuid() != 0 {
		return fmt.Errorf("root user in required for this process or container")
	}
	cmd := exec.Command("make", "load")
	cmd.Env = os.Environ()
	if useCniMode {
		cmd.Env = append(cmd.Env, "CNI_MODE=true")
	}
	if !kernelTracing {
		cmd.Env = append(cmd.Env, "DEBUG=0")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("unexpected exit code: %d, err: %v", code, err)
	}
	return nil
}

// UnLoadProgs unload ebpf progs
func UnLoadProgs() error {
	cmd := exec.Command("make", "-k", "clean")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("unload unexpected exit code: %d, err: %v", code, err)
	}
	return nil
}

var (
	ingress *ebpf.Program
	egress  *ebpf.Program
)

// GetTrafficControlIngressProg returns tc ingress ebpf prog
func GetTrafficControlIngressProg() *ebpf.Program {
	if ingress == nil {
		var err error
		ingress, err = ebpf.LoadPinnedProgram("/sys/fs/bpf/fsm/classifier_sidecar_ingress", nil)
		if err != nil {
			log.Error().Msgf("init ingress tc prog filed: %v", err)
		}
	}
	return ingress
}

// GetTrafficControlEgressProg returns tc egress ebpf prog
func GetTrafficControlEgressProg() *ebpf.Program {
	if egress == nil {
		var err error
		egress, err = ebpf.LoadPinnedProgram("/sys/fs/bpf/fsm/classifier_sidecar_egress", nil)
		if err != nil {
			log.Error().Msgf("init egress tc prog filed: %v", err)
		}
	}
	return egress
}
