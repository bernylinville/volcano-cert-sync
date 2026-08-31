# Deployment examples

These files are deliberately generic and safe to publish. They demonstrate the
least-privilege runtime shape, but they are **not** the production deployment
source of truth. Put real namespaces, source Secret names, domains, registry
digests, cloud credentials, and MCDN request templates in the private GitOps
repository as encrypted secrets.

The production design uses one CronJob per source TLS Secret, running every six
hours with `concurrencyPolicy: Forbid`. It performs a true dry-run before the
first live job and pins the image by digest.

To validate the examples locally:

```bash
kustomize build deploy/example | kubeconform -strict -summary -ignore-missing-schemas
```

Do not apply `deploy/example` to a production cluster unchanged.
