// Package main implements the main entrypoint for fsm-ztm-agent and utility routines to
// bootstrap the various internal components of fsm-connector.
package main

import (
	"context"
	"net/http"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/flomesh-io/fsm/pkg/configurator"
	"github.com/flomesh-io/fsm/pkg/constants"
	"github.com/flomesh-io/fsm/pkg/errcode"
	configClientset "github.com/flomesh-io/fsm/pkg/gen/client/config/clientset/versioned"
	multiclusterClientset "github.com/flomesh-io/fsm/pkg/gen/client/multicluster/clientset/versioned"
	mcscheme "github.com/flomesh-io/fsm/pkg/gen/client/multicluster/clientset/versioned/scheme"
	ztmClientset "github.com/flomesh-io/fsm/pkg/gen/client/ztm/clientset/versioned"
	ztmscheme "github.com/flomesh-io/fsm/pkg/gen/client/ztm/clientset/versioned/scheme"
	"github.com/flomesh-io/fsm/pkg/health"
	"github.com/flomesh-io/fsm/pkg/httpserver"
	"github.com/flomesh-io/fsm/pkg/k8s"
	"github.com/flomesh-io/fsm/pkg/k8s/events"
	"github.com/flomesh-io/fsm/pkg/k8s/informers"
	"github.com/flomesh-io/fsm/pkg/logger"
	"github.com/flomesh-io/fsm/pkg/messaging"
	"github.com/flomesh-io/fsm/pkg/providers/kube"
	_ "github.com/flomesh-io/fsm/pkg/sidecar/providers/pipy/driver"
	"github.com/flomesh-io/fsm/pkg/signals"
	"github.com/flomesh-io/fsm/pkg/version"
	"github.com/flomesh-io/fsm/pkg/ztm"
	"github.com/flomesh-io/fsm/pkg/ztm/cli"
)

var (
	log    = logger.New("fsm-ztm-agent")
	scheme = runtime.NewScheme()
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = mcscheme.AddToScheme(scheme)
	_ = ztmscheme.AddToScheme(scheme)
}

func main() {
	log.Info().Msgf("Starting fsm-ztm-agent %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)
	if err := cli.ParseFlags(); err != nil {
		log.Fatal().Err(err).Msg("Error parsing cmd line arguments")
	}

	// This ensures CLI parameters (and dependent values) are correct.
	if err := cli.ValidateCLIParams(); err != nil {
		log.Fatal().Err(err).Msg("Error validating CLI parameters")
	}

	if err := logger.SetLogLevel(cli.Verbosity()); err != nil {
		log.Fatal().Err(err).Msg("Error setting log level")
	}

	// Initialize kube config and client
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", cli.Cfg.KubeConfigFile)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error creating kube config (kubeconfig=%s)", cli.Cfg.KubeConfigFile)
	}
	kubeClient := kubernetes.NewForConfigOrDie(kubeConfig)
	ztmClient := ztmClientset.NewForConfigOrDie(kubeConfig)
	mcsClient := multiclusterClientset.NewForConfigOrDie(kubeConfig)

	// Initialize the generic Kubernetes event recorder and associate it with the fsm-ztm-agent pod resource
	ztmAgentPod, err := cli.GetZtmAgentPod(kubeClient)
	if err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrFetchingConnectorPod)).
			Msg("Error retrieving fsm-ztm-agent pod")
		log.Fatal().Msg("Error fetching fsm-ztm-agent pod")
	}

	eventRecorder := events.GenericEventRecorder()
	if err = eventRecorder.Initialize(ztmAgentPod, kubeClient, cli.Cfg.FsmNamespace); err != nil {
		log.Fatal().Msg("Error initializing generic event recorder")
	}

	k8s.SetTrustDomain(cli.Cfg.TrustDomain)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := signals.RegisterExitHandlers(cancel)

	msgBroker := messaging.NewBroker(stop)
	configClient := configClientset.NewForConfigOrDie(kubeConfig)
	informerCollection, err := informers.NewInformerCollection(cli.Cfg.MeshName, stop,
		informers.WithKubeClient(kubeClient),
		informers.WithConfigClient(configClient, cli.Cfg.FsmMeshConfigName, cli.Cfg.FsmNamespace),
		informers.WithZtmClient(ztmClient),
		informers.WithMultiClusterClient(mcsClient),
	)
	if err != nil {
		events.GenericEventRecorder().FatalEvent(err, events.InitializationError, "Error creating informer collection")
	}

	cfg := configurator.NewConfigurator(informerCollection, cli.Cfg.FsmNamespace, cli.Cfg.FsmMeshConfigName, msgBroker)
	k8sController := k8s.NewKubernetesController(informerCollection, nil, nil, msgBroker)
	kubeProvider := kube.NewClient(k8sController, cfg)

	agentController := cli.NewAgentController(ctx,
		cli.Cfg.ZtmAgent,
		kubeConfig,
		k8sController,
		kubeProvider,
		configClient,
		ztmClient,
		informerCollection,
		msgBroker)
	clusterSet := cfg.GetMeshConfig().Spec.ClusterSet
	agentController.SetClusterSet(clusterSet.Name, clusterSet.Group, clusterSet.Zone, clusterSet.Region)

	go agentController.BroadcastListener(stop)

	version.SetMetric()
	/*
	 * Initialize fsm-ztm-agent's HTTP server
	 */
	httpServer := httpserver.NewHTTPServer(constants.FSMHTTPServerPort)
	// Version
	httpServer.AddHandler(constants.VersionPath, version.GetVersionHandler())
	// Health checks
	httpServer.AddHandler(constants.WebhookHealthPath, http.HandlerFunc(health.SimpleHandler))

	// Start HTTP server
	err = httpServer.Start()
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to start FSM metrics/probes HTTP server")
	}

	// Start the global log level watcher that updates the log level dynamically
	go ztm.WatchMeshConfigUpdated(agentController, msgBroker, stop)

	<-stop
	log.Info().Msgf("Stopping fsm-ztm-agent %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)
}
