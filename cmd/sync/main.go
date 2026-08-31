// volcano-cert-sync reconciles one Kubernetes TLS Secret to explicit
// Volcengine acceleration targets. It is intentionally a one-shot process so
// Kubernetes CronJob controls scheduling and duplicate-run prevention.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/bernylinville/volcano-cert-sync/internal/config"
	"github.com/bernylinville/volcano-cert-sync/internal/k8s"
	"github.com/bernylinville/volcano-cert-sync/internal/syncer"
	"github.com/bernylinville/volcano-cert-sync/internal/volcengine"
)

var version = "dev"

func main() {
	dryRun := flag.Bool("dry-run", false, "Read and validate all state without cloud writes")
	showVersion := flag.Bool("version", false, "Print the release version and exit")
	flag.Parse()
	if *showVersion {
		_, _ = os.Stdout.WriteString(version + "\n")
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(context.Background(), logger, *dryRun); err != nil {
		logger.Error("certificate synchronization failed", "error", safeError(err))
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, flagDryRun bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	dryRun := cfg.DryRun || flagDryRun
	logger.Info("starting certificate reconciliation", "dry_run", dryRun, "targets", targetNames(cfg.SyncTargets))

	kubernetesClient, err := k8s.NewClient()
	if err != nil {
		return err
	}
	certificate, err := kubernetesClient.GetTLSSecret(ctx, cfg.SecretNamespace, cfg.SecretName)
	if err != nil {
		return err
	}
	logger.Info("validated Kubernetes TLS Secret",
		"namespace", cfg.SecretNamespace,
		"name", cfg.SecretName,
		"fingerprint", certificate.ShortFingerprint(),
		"not_after", certificate.Leaf.NotAfter.UTC().Format(time.RFC3339),
	)

	backends, err := volcengine.NewBackends(cfg.VolcAccessKey, cfg.VolcSecretKey, cfg.MCDNDeployRequestTemplate)
	if err != nil {
		return err
	}
	targets := make([]syncer.Target, 0, len(cfg.SyncTargets))
	for _, target := range cfg.SyncTargets {
		targets = append(targets, syncer.Target{Domain: target.Domain, Type: string(target.Type)})
	}

	service := syncer.Service{
		Backends: backends,
		Options: syncer.Options{
			DryRun: dryRun,
			Report: func(event syncer.Event) {
				logger.Info("certificate reconciliation event",
					"stage", event.Stage,
					"target_type", event.TargetType,
					"domain", event.Domain,
					"action", event.Action,
					"fingerprint", event.Fingerprint,
					"message", event.Message,
				)
			},
		},
	}
	result, err := service.Sync(ctx, certificate, targets)
	for _, domain := range sortedResultDomains(result) {
		logger.Info("certificate reconciliation result", "domain", domain, "result", result.Targets[domain])
	}
	if err != nil {
		return err
	}
	logger.Info("certificate reconciliation completed", "dry_run", dryRun)
	return nil
}

func targetNames(targets []config.SyncTarget) []string {
	result := make([]string, 0, len(targets))
	for _, target := range targets {
		result = append(result, string(target.Type)+":"+target.Domain)
	}
	sort.Strings(result)
	return result
}

func sortedResultDomains(result syncer.Result) []string {
	domains := make([]string, 0, len(result.Targets))
	for domain := range result.Targets {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	// The application wraps errors using API names, domains, and status only.
	// Avoid `%+v`, which some SDKs use to render full request structures.
	return err.Error()
}
