# Flomesh Service Mesh Helm Chart

![Version: 1.4.0-alpha.1](https://img.shields.io/badge/Version-1.4.0--alpha.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.4.0-alpha.1](https://img.shields.io/badge/AppVersion-1.4.0--alpha.1-informational?style=flat-square)

A Helm chart to install the [fsm](https://github.com/flomesh-io/fsm) control plane on Kubernetes.

## Prerequisites

- Kubernetes >= 1.19.0-0

## Get Repo Info

```console
helm repo add fsm https://flomesh-io.github.io/fsm
helm repo update
```

## Install Chart

```console
helm install [RELEASE_NAME] fsm/fsm
```

The command deploys `fsm-controller` on the Kubernetes cluster in the default configuration.

_See [configuration](#configuration) below._

_See [helm install](https://helm.sh/docs/helm/helm_install/) for command documentation._

## Uninstall Chart

```console
helm uninstall [RELEASE_NAME]
```

This removes all the Kubernetes components associated with the chart and deletes the release.

_See [helm uninstall](https://helm.sh/docs/helm/helm_uninstall/) for command documentation._

## Upgrading Chart

```console
helm upgrade [RELEASE_NAME] [CHART] --install
```

_See [helm upgrade](https://helm.sh/docs/helm/helm_upgrade/) for command documentation._

## Configuration

See [Customizing the Chart Before Installing](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing). To see all configurable options with detailed comments, visit the chart's [values.yaml](./values.yaml), or run these configuration commands:

```console
helm show values fsm/fsm
```

The following table lists the configurable parameters of the fsm chart and their default values.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| fsm.controllerLogLevel | string | `"info"` | Controller log verbosity |
| fsm.fsmNamespace | string | `""` | Namespace to deploy FSM in. If not specified, the Helm release namespace is used. |
| fsm.image.digest | object | `{"fsmCurl":"","ztmController":""}` | Image digest (defaults to latest compatible tag) |
| fsm.image.digest.fsmCurl | string | `""` | fsm-curl's image digest |
| fsm.image.digest.ztmController | string | `""` | fsm-ztm-agent's image digest |
| fsm.image.name | object | `{"fsmCurl":"fsm-curl","ztmController":"fsm-ztm-agent"}` | Image name defaults |
| fsm.image.name.fsmCurl | string | `"fsm-curl"` | fsm-curl's image name |
| fsm.image.name.ztmController | string | `"fsm-ztm-agent"` | fsm-ztm-agent's image name |
| fsm.image.pullPolicy | string | `"IfNotPresent"` | Container image pull policy for control plane containers |
| fsm.image.registry | string | `"flomesh"` | Container image registry for control plane images |
| fsm.image.tag | string | `"1.4.0-alpha.1"` | Container image tag for control plane images |
| fsm.imagePullSecrets | list | `[]` | `fsm-ztm-agent` image pull secret |
| fsm.meshName | string | `"fsm"` | Identifier for the instance of a service mesh within a cluster |
| fsm.trustDomain | string | `"cluster.local"` | The trust domain to use as part of the common name when requesting new certificates. |
| fsm.ztm.image.name | string | `"ztm-agent"` | ztm image name |
| fsm.ztm.image.registry | string | `"cybwan"` | Registry for ztm image |
| fsm.ztm.image.tag | string | `"0.2.0"` | ztm image tag |
| fsm.ztmController.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key | string | `"kubernetes.io/os"` |  |
| fsm.ztmController.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator | string | `"In"` |  |
| fsm.ztmController.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0] | string | `"linux"` |  |
| fsm.ztmController.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[1].key | string | `"kubernetes.io/arch"` |  |
| fsm.ztmController.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[1].operator | string | `"In"` |  |
| fsm.ztmController.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[1].values[0] | string | `"amd64"` |  |
| fsm.ztmController.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[1].values[1] | string | `"arm64"` |  |
| fsm.ztmController.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.labelSelector.matchExpressions[0].key | string | `"app"` |  |
| fsm.ztmController.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.labelSelector.matchExpressions[0].operator | string | `"In"` |  |
| fsm.ztmController.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.labelSelector.matchExpressions[0].values[0] | string | `"fsm-injector"` |  |
| fsm.ztmController.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.topologyKey | string | `"kubernetes.io/hostname"` |  |
| fsm.ztmController.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].weight | int | `100` |  |
| fsm.ztmController.agentResources | object | `{"limits":{"cpu":"500m","memory":"512M"},"requests":{"cpu":"200m","memory":"128M"}}` | agentContainer resource parameters |
| fsm.ztmController.autoScale | object | `{"cpu":{"targetAverageUtilization":80},"enable":false,"maxReplicas":5,"memory":{"targetAverageUtilization":80},"minReplicas":1}` | Auto scale configuration |
| fsm.ztmController.autoScale.cpu.targetAverageUtilization | int | `80` | Average target CPU utilization (%) |
| fsm.ztmController.autoScale.enable | bool | `false` | Enable Autoscale |
| fsm.ztmController.autoScale.maxReplicas | int | `5` | Maximum replicas for autoscale |
| fsm.ztmController.autoScale.memory.targetAverageUtilization | int | `80` | Average target memory utilization (%) |
| fsm.ztmController.autoScale.minReplicas | int | `1` | Minimum replicas for autoscale |
| fsm.ztmController.enable | bool | `false` |  |
| fsm.ztmController.enablePodDisruptionBudget | bool | `false` | Enable Pod Disruption Budget |
| fsm.ztmController.initResources | object | `{"limits":{"cpu":"500m","memory":"512M"},"requests":{"cpu":"200m","memory":"128M"}}` | initContainer resource parameters |
| fsm.ztmController.name | string | `""` |  |
| fsm.ztmController.nodeSelector | object | `{}` |  |
| fsm.ztmController.podLabels | object | `{}` |  |
| fsm.ztmController.replicaCount | int | `1` |  |
| fsm.ztmController.resource.limits.cpu | string | `"1"` |  |
| fsm.ztmController.resource.limits.memory | string | `"1G"` |  |
| fsm.ztmController.resource.requests.cpu | string | `"0.5"` |  |
| fsm.ztmController.resource.requests.memory | string | `"128M"` |  |
| fsm.ztmController.tolerations | list | `[]` | Node tolerations applied to control plane pods. The specified tolerations allow pods to schedule onto nodes with matching taints. |

<!-- markdownlint-enable MD013 MD034 -->
<!-- markdownlint-restore -->