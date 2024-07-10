/*
 * MIT License
 *
 * Copyright (c) since 2021,  flomesh.io Authors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// Package v1alpha1 contains controller logic for the ztm API v1alpha1.
package v1alpha1

import (
	_ "embed"
	"fmt"

	"helm.sh/helm/v3/pkg/strvals"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"

	ztmv1 "github.com/flomesh-io/fsm/pkg/apis/ztm/v1alpha1"
	"github.com/flomesh-io/fsm/pkg/configurator"
	"github.com/flomesh-io/fsm/pkg/constants"
	fctx "github.com/flomesh-io/fsm/pkg/context"
	ztmClientset "github.com/flomesh-io/fsm/pkg/gen/client/ztm/clientset/versioned"
	"github.com/flomesh-io/fsm/pkg/helm"
	"github.com/flomesh-io/fsm/pkg/logger"
)

var (
	log = logger.New("ztm-controller/v1alpha1")
)

var (
	//go:embed chart.tgz
	chartSource []byte
)

type ztmReconciler struct {
	recorder     record.EventRecorder
	fctx         *fctx.ControllerContext
	ztmAPIClient ztmClientset.Interface
}

func (r *ztmReconciler) NeedLeaderElection() bool {
	return true
}

func (r *ztmReconciler) deployZtmMember(member ztmv1.ZtmMember, mc configurator.Configurator) (ctrl.Result, error) {
	actionConfig := helm.ActionConfig(member.GetNamespace(), log.Debug().Msgf)

	templateClient := helm.TemplateClient(
		actionConfig,
		r.fctx.MeshName,
		mc.GetFSMNamespace(),
		constants.KubeVersion121,
	)
	if ctrlResult, err := helm.RenderChart(templateClient, member, chartSource, mc, r.fctx.Client, r.fctx.Scheme, r.resolveValues); err != nil {
		defer r.recorder.Eventf(member, corev1.EventTypeWarning, "Deploy", "Failed to deploy ztm member: %s", err)
		return ctrlResult, err
	}
	defer r.recorder.Eventf(member, corev1.EventTypeNormal, "Deploy", "Deploy ztm member successfully")

	return ctrl.Result{}, nil
}

func (r *ztmReconciler) resolveValues(object metav1.Object, mc configurator.Configurator) (map[string]interface{}, error) {
	member, ok := object.(ztmv1.ZtmMember)
	if !ok {
		return nil, fmt.Errorf("object %v is not type of *ztmv1alpha1.ZtmMember", object)
	}

	log.Debug().Msgf("[GW] Resolving Values ...")

	finalValues := make(map[string]interface{})

	overrides := []string{
		fmt.Sprintf("fsm.image.registry=%s", mc.GetImageRegistry()),
		fmt.Sprintf("fsm.image.tag=%s", mc.GetImageTag()),
		fmt.Sprintf("fsm.image.pullPolicy=%s", mc.GetImagePullPolicy()),

		fmt.Sprintf("fsm.meshName=%s", r.fctx.MeshName),
		fmt.Sprintf("fsm.fsmNamespace=%s", mc.GetFSMNamespace()),
		fmt.Sprintf("fsm.trustDomain=%s", r.fctx.TrustDomain),

		fmt.Sprintf("fsm.controllerLogLevel=%s", mc.GetZtmLogLevel()),

		fmt.Sprintf("fsm.ztmController.enable=%t", true),
		fmt.Sprintf("fsm.ztmController.name=%s", member.GetName()),

		fmt.Sprintf("fsm.ztmController.replicaCount=%d", replicas(member, 1)),
		fmt.Sprintf("fsm.ztmController.resource.requests.cpu='%s'", requestsCpu(member, resource.MustParse("0.5")).String()),
		fmt.Sprintf("fsm.ztmController.resource.requests.memory=%s", requestsMem(member, resource.MustParse("128M")).String()),
		fmt.Sprintf("fsm.ztmController.resource.limits.cpu='%s'", limitsCpu(member, resource.MustParse("1")).String()),
		fmt.Sprintf("fsm.ztmController.resource.limits.memory=%s", limitsMem(member, resource.MustParse("1G")).String()),
	}

	for _, ov := range overrides {
		if err := strvals.ParseInto(ov, finalValues); err != nil {
			return nil, err
		}
	}

	return finalValues, nil
}

func replicas(member ztmv1.ZtmMember, defVal int32) int32 {
	if member.GetReplicas() == nil {
		return defVal
	}
	return *member.GetReplicas()
}

func requestsCpu(member ztmv1.ZtmMember, defVal resource.Quantity) *resource.Quantity {
	if member.GetResources() == nil {
		return &defVal
	}

	if member.GetResources().Requests.Cpu() == nil {
		return &defVal
	}

	if member.GetResources().Requests.Cpu().Value() == 0 {
		return &defVal
	}

	return member.GetResources().Requests.Cpu()
}

func requestsMem(member ztmv1.ZtmMember, defVal resource.Quantity) *resource.Quantity {
	if member.GetResources() == nil {
		return &defVal
	}

	if member.GetResources().Requests.Memory() == nil {
		return &defVal
	}

	if member.GetResources().Requests.Memory().Value() == 0 {
		return &defVal
	}

	return member.GetResources().Requests.Memory()
}

func limitsCpu(member ztmv1.ZtmMember, defVal resource.Quantity) *resource.Quantity {
	if member.GetResources() == nil {
		return &defVal
	}

	if member.GetResources().Limits.Cpu() == nil {
		return &defVal
	}

	if member.GetResources().Limits.Cpu().Value() == 0 {
		return &defVal
	}

	return member.GetResources().Limits.Cpu()
}

func limitsMem(member ztmv1.ZtmMember, defVal resource.Quantity) *resource.Quantity {
	if member.GetResources() == nil {
		return &defVal
	}

	if member.GetResources().Limits.Memory() == nil {
		return &defVal
	}

	if member.GetResources().Limits.Memory().Value() == 0 {
		return &defVal
	}

	return member.GetResources().Limits.Memory()
}
