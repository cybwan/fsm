# E2E FSM Testing
## Table of Contents
- [Overview](#overview)
- [Files and structure](#files-and-structure)
- [Running the tests](#running-the-tests)
  - [Kind cluster](#kind-cluster)
  - [Other K8s deployment](#other-k8s-deployment)
  - [Flags](#flags)

## Overview
End-to-end tests verify the behavior of the entire system. For FSM, e2e tests will install a control plane, install test workloads and SMI policies, and check that the workload is behaving as expected.

## Files and structure
FSM's e2e tests are located in `tests/e2e`.
The tests are written using Ginkgo and Gomega so they may also be directly invoked using `go test`. Be sure to build the `fsm-controller` and `init` container images and `fsm` CLI before directly invoking the tests ([see instructions below](#running-the-tests)).

FSM's framework, helpers and related files are located under `tests/framework`.
Once imported, it automatically sets up an init mechanism which will automatically initialize and parse flags and variables from both `env` and `go test flags` if any are passed to the test. The hooks for initialization and cleanup are set at Ginkgo's `BeforeEach` at the top level of test execution (between Ginkgo `Describes`); we henceforth recommend keeping every test in its own `Describe` section, as well as on a separate file for clarity. You can refer to [common.go](tests/framework/common.go) for more details about the init, setup and cleanup processes.

### Test organization

Tests are organized by top-level `Describe` blocks into buckets. Each bucket runs in parallel, and individual tests in the bucket run sequentially.

To help organize the tests, a custom `Describe` block named `FSMDescribe` is provided which accepts an additional struct parameter which contains fields for test metadata like tier and bucket. `FSMDescribe` will construct a well-formatted name including the test metadata which can be used in CI to run tests accordingly. Ginkgo's original `Describe` should not be used directly at the top-level and `FSMDescribe` should be used instead.

## Running the tests
Running the tests will require a running Kubernetes cluster. If you do not have a Kubernetes cluster to run the tests onto, you can choose to run them using `Kind`, which will make the test framework initialize a cluster on a local accessible docker client.

Running the tests will also require the [Helm](https://helm.sh/) CLI to be installed on your machine.

The tests can be run using the `test-e2e` Makefile target at repository root level (which defaults to use Kind), or alternatively `go test` targetting the test folder, which gives more flexibility but depends on related `env` flags given or parsed by the test.

Please refer to the [Kind cluster](#kind-cluster) or [Other K8s deployment](#other-k8s-eployment) and follow the instructions to setup potential env flags required by either option.

In addition to the flags provided by `go test` and Ginkgo, there are several custom command line flags that may be used for e2e tests to configure global parameters like container image locations and cleanup behavior. You can see the list of flags under the [flag section](#flags) below.

### Kind cluster
The following `make` target will create local containers for the FSM components, tagging them with `CTR_TAG`, and will launch the tests using Kind cluster. A Kind cluster is created at test start, and requires a docker interface to be available on the host running the test.
When using Kind, we load the images onto the Kind nodes directly (as opposed to providing a registry to pull the images from).
```
CTR_TAG=not-latest make test-e2e
```
Note: If you use `latest` tag, K8s will try to pull the image by default. If the images are not pushed to a registry accessible by the kind cluster, image pull errors will occur. Or, if an image with the same name is available, like `flomesh/fsm-init:latest`, then that publicly available image will be pulled and started instead, which may not be as up-to-date as the local image already loaded onto the cluster.

### Other K8s deployment
Have your Kubeconfig file point to your testing cluster of choice.
The following code uses `latest` tag by default. Non-Kind deployments do not push the images on the nodes, so make sure to set the registry accordingly.
```
export CTR_REGISTRY=<myacr>.dockerhub.io # if needed, set CTR_REGISTRY_USER and CTR_REGISTRY_PASSWORD
make build-fsm
make docker-build
go test ./tests/e2e -test.v -ginkgo.v -ginkgo.progress
```

### Flags
#### (TODO) Kubeconfig selection
Currently, test init will load a `Kubeconf` based on default kubeconfig loading rules.
If Kind is used, the kubeconf is temporarily replaced and Kind's kubeconf is used instead.

#### Container registry
A container registry where to load the images from (FSM, init container, etc.). Credentials are optional if the container registry allows pulling the images publicly:
```
-ctrRegistry string
		Container registry
-ctrRegistrySecret string
		Container registry secret
-ctrRegistryUser string
		Container registry username
```
If container registry user and password are provided, the test framework will take care to add those as Docker secret credentials for the given container registry whenever appropriate (tenant namespaces for `init` containers, FSM intallation, etc).
Container registry related flags can also be set through env:
```
export CTR_REGISTRY=<your_cr>.dockerhub.io
export CTR_REGISTRY_USER=<uername>             # opt
export CTR_REGISTRY_PASSWORD=<password>        # opt
```

#### FSM Tag
The following flag will refer to the image version of the FSM platform containers (`fsm-controller` and `init`) and `tcp-echo-server` for the tests to use:
```
-fsmImageTag string
		FSM image tag (default "latest")
```
Make sure you have compiled the images and pushed them on your registry first if you are not using a kind cluster:
```
export CTR_REGISTRY=myacr.dockerhub.io
export CTR_TAG=mytag               # Optional, 'latest' used by default
make docker-build-fsm    # Add DOCKER_BUILDX_OUTPUT=type=docker when using kind
```

#### Test specific flags

Worth mentioning `cleanupTest` is especially useful for debugging or leaving the test in a certain state at test-exit.
When using Kind, you need to use `cleanupCluster` and `cleanupClusterBetweenTests` in conjunction, or else the cluster
will anyway be destroyed.
```
-cleanupTest
		Cleanup test resources when done (default true)
-meshName string
		FSM mesh name (default "fsm-system")
-waitForCleanup
		Wait for effective deletion of resources (default true)
```
Plus, `go test` and `Ginkgo` specific flags, of course.

#### Running individual tests:

The `ginkgo.focus` flag can be used to run individual tests. The flag should specify the "Context" of the test they wish to run, which can be found in the `.go` file for that test. For instance, if you want to run the `e2e_tcp_client_server_test` with SMI policies, you should run:

```console
go test ./tests/e2e -test.v -ginkgo.v -ginkgo.progress -ginkgo.focus="\bSimpleClientServer TCP with SMI policies\b"
```

#### Setting installType:

The `installType` flag can be used to specify whether the tests should install FSM themselves, or if they will be run on a cluster which already has FSM installed.

```console
go test ./tests/e2e -test.v -ginkgo.v -ginkgo.progress -installType=NoInstall
```

The different values of installType are as follows:

1. `installType=NoInstall`

    The e2es will run on the cluster currently in the user's kubeconfig, which is already expected to have FSM installed prior to the test run. The tests will not install FSM before, or uninstall FSM after any of the tests run. The cluster can be of any CNCF certified distribution (though the k8s version cannot be an outdated version).

2. `installType=KindCluster`

	Each test in the e2e suite will spin up a kind cluster, and run that specific test on that kind cluster. Each test will install FSM via the FSM cli, and then uninstall FSM after the test finishes running. The user is not expected to have created any cluster beforehand.

3. `installType=K3dCluster`

   Each test in the e2e suite will spin up a k3d cluster, and run that specific test on that k3d cluster. Each test will install FSM via the FSM cli, and then uninstall FSM after the test finishes running. The user is not expected to have created any cluster beforehand.

4. `installType=SelfInstall` (default)

	By default, the e2es will run on the cluster currently in the user's kubeconfig. Each test will install FSM via the FSM cli, and then uninstall FSM after the test finishes running. The cluster can be of any CNCF certified distribution (though the k8s version cannot be an outdated version). The user is should not have FSM installed beforehand.


#### Use Kind for testing
Testing implements support for Kind. If `installType=KindCluster` is enabled, a new Kind cluster will be provisioned and it will be automatically used for the test.

```
-clusterName string
		Name of the Kind cluster to be created (default "fsm-e2e")
-cleanupCluster
		Cleanup kind cluster upon exit (default true)
-cleanupClusterBetweenTests
		Cleanup kind cluster between tests (default true)
```

#### Use K3d for testing
Testing implements support for K3d. If `installType=K3dCluster` is enabled, a new K3d cluster will be provisioned and it will be automatically used for the test.

```
-clusterName string
		Name of the K3d cluster to be created (default "fsm-e2e")
-cleanupCluster
		Cleanup k3d cluster upon exit (default true)
-cleanupClusterBetweenTests
		Cleanup k3d cluster between tests (default true)
```

#### Setting test timeout:

The `test.timeout` flag sets a total time limit for all the tests that you are running. If you run the e2es without specifying any timeout limit, the tests will terminate after 10 minutes. To run the tests without any time limit, you should set `test.timeout 0`.

To set a specific time limit, a unit must be specified along with a number. For instance, if you want to set the limit to 90 seconds (say for just testing one e2e), you should say `test.timeout 90s`. If you want the tests to run for 60 minutes, you should say `test.timeout 60m`.

#### OpenShift:
OpenShift compatibility is still a WIP for the e2e tests.

To run these tests on OpenShift
1. Install the [oc CLI](https://docs.openshift.com/container-platform/4.7/cli_reference/openshift_cli/getting-started-cli.html).
1. Include `-deployOnOpenShift=true` with your `go test` command.
