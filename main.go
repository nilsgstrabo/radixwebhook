package main

import (
	"crypto/tls"
	"fmt"
	"net/http"

	radixv1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	radixv2 "github.com/equinor/radix-operator/pkg/apis/radix/v2"
	"github.com/equinor/radix-operator/pkg/apis/radixvalidators"
	pkgwebhook "github.com/nilsgstrabo/radixwebhook/pkg/webhook"
	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"sigs.k8s.io/controller-runtime/pkg/webhook/conversion"
)

var webhooks = []rotator.WebhookInfo{
	{
		Name: "radix-admission-webhook",
		Type: rotator.Validating,
	},
	{
		Name: "radixapplications.radix.equinor.com",
		Type: rotator.CRDConversion,
	},
}

const (
	secretName     = "radix-webhook-server-cert" // #nosec
	serviceName    = "radix-webhook-service"
	caName         = "radix-ca"
	caOrganization = "radix"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(radixv1.AddToScheme(scheme))
	utilruntime.Must(radixv2.AddToScheme(scheme))
}

func main() {
	if err := mainErr(); err != nil {
		log.Panic().Err(err).Msg("Problem running webhooks")
	}
}

func mainErr() error {
	var (
		healthAddr          string
		metricsAddr         string
		webhooksPort        int
		webhookCertDir      string
		dnsName             = fmt.Sprintf("%s.%s.svc", serviceName, "radix-system")
		disableCertRotation bool
	)

	pflag.StringVar(&healthAddr, "health-addr", ":9440", "The address the health endpoint binds to")
	pflag.StringVar(&metricsAddr, "metrics-address", ":8080", "The address the metric endpoint binds to.")
	pflag.IntVar(&webhooksPort, "port", 9443, "Port number to serve webhooks. Defaults to 9443")
	pflag.StringVar(&webhookCertDir, "webhook-cert-dir", "/certs", "Webhook certificates dir to use. Defaults to /certs")
	pflag.BoolVar(&disableCertRotation, "disable-cert-rotation", false, "disable automatic generation and rotation of webhook TLS certificates/keys")
	pflag.Parse()
	ctx := signals.SetupSignalHandler()

	ctrl.SetLogger(zap.New(zap.ConsoleEncoder()))

	cfg := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		LeaderElection:         false,
		HealthProbeBindAddress: healthAddr,
		Metrics: server.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    webhooksPort,
			CertDir: webhookCertDir,
			TLSOpts: []func(*tls.Config){
				func(c *tls.Config) { c.MinVersion = tls.VersionTLS13 },
			},
		}),
		// MapperProvider: apiutil.NewDynamicRESTMapper,
	})
	if err != nil {
		return fmt.Errorf("failed to set up webhook manager: %w", err)
	}

	setupFinished := make(chan struct{})
	if !disableCertRotation {
		err = rotator.AddRotator(mgr, &rotator.CertRotator{
			SecretKey: types.NamespacedName{
				Name:      secretName,
				Namespace: "radix-system",
			},
			CertDir:        webhookCertDir,
			CAName:         caName,
			CAOrganization: caOrganization,
			DNSName:        dnsName,
			ExtraDNSNames:  []string{dnsName},
			Webhooks:       webhooks,
			IsReady:        setupFinished,
		})
		if err != nil {
			return fmt.Errorf("failed to set up cert rotator: %w", err)
		}
	} else {
		close(setupFinished)
	}

	go func() {
		<-setupFinished
		log.Info().Msg("set up finished")
	}()

	setupProbeEndpoints(mgr, setupFinished)
	go setupWebhook(mgr, setupFinished)

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start manager: %w", err)
	}

	return nil
}

func setupWebhook(mgr manager.Manager, setupFinished chan struct{}) {
	// Block until the setup (certificate generation) finishes.
	<-setupFinished

	hookServer := mgr.GetWebhookServer()

	// setup webhooks
	mgr.GetLogger().Info("registering webhook to the webhook server")

	raValidation := func(obj *radixv1.RadixApplication) ([]string, error) {
		return nil, radixvalidators.IsRadixApplicationValid(obj)
	}

	hookServer.Register("/radix/v1/radixapplication/validate", admission.WithCustomValidator(scheme, &radixv1.RadixApplication{}, &pkgwebhook.AdmissionValidator[*radixv1.RadixApplication]{
		Logger:           mgr.GetLogger(),
		CreateValidation: raValidation,
		UpdateValidation: raValidation,
	}))

	rrValidation := func(obj *radixv1.RadixRegistration) ([]string, error) {
		return nil, radixvalidators.CanRadixRegistrationBeUpdated(obj)
	}

	hookServer.Register("/radix/v1/radixregistration/validate", admission.WithCustomValidator(scheme, &radixv1.RadixRegistration{}, &pkgwebhook.AdmissionValidator[*radixv1.RadixRegistration]{
		Logger:           mgr.GetLogger(),
		CreateValidation: rrValidation,
		UpdateValidation: rrValidation,
	}))

	hookServer.Register("/convert", conversion.NewWebhookHandler(mgr.GetScheme()))

}

func setupProbeEndpoints(mgr ctrl.Manager, setupFinished chan struct{}) {
	// Block readiness on the mutating webhook being registered.
	// We can't use mgr.GetWebhookServer().StartedChecker() yet,
	// because that starts the webhook. But we also can't call AddReadyzCheck
	// after Manager.Start. So we need a custom ready check that delegates to
	// the real ready check after the cert has been injected and validator started.
	checker := func(req *http.Request) error {
		select {
		case <-setupFinished:
			return mgr.GetWebhookServer().StartedChecker()(req)
		default:
			return fmt.Errorf("certs are not ready yet")
		}
	}

	if err := mgr.AddHealthzCheck("healthz", checker); err != nil {
		panic(fmt.Errorf("unable to add healthz check: %w", err))
	}
	if err := mgr.AddReadyzCheck("readyz", checker); err != nil {
		panic(fmt.Errorf("unable to add readyz check: %w", err))
	}
	mgr.GetLogger().Info("added healthz and readyz check")
}
