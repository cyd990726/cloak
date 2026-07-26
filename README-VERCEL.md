# Vercel Serverless Deployment

This project can run on Vercel through the Go Serverless Function in `api/index.go`.

## Deploy

1. Import `https://github.com/cyd990726/cloak` in Vercel.
2. Keep the framework preset as `Other`.
3. Use the project root as the root directory.
4. Add environment variables:

```text
CLOAK_SECRET_KEY=<random hex string>
CLOAK_COUNTRY_DB=data/BIT4BF5.tmp
CLOAK_ADMIN_TOKEN=<random admin debug token>
CLOAK_API_TOKEN=<random server-to-server token>
```

Generate a local secret value with:

```bash
openssl rand -hex 32
```

`vercel.json` rewrites all routes to the Go function while preserving the original path, so existing routes such as `/healthz`, `/app`, `/shop`, `/chat`, `/contact`, `/validate`, and `/_beh` continue to work.

`CLOAK_ADMIN_TOKEN` protects `/admin`, `/judge`, and `/__vercel_debug`. To use those debug endpoints, send either:

```text
X-Admin-Token: <token>
```

or append:

```text
?debug_token=<token>
```

`CLOAK_API_TOKEN` protects the JSON judgment API:

```text
POST /api/judge
X-Cloak-Token: <token>
```

The judgment API returns an A/B audience result:

```json
{
  "audience": "A",
  "allow_return": false,
  "action": "review",
  "score": 50,
  "total_max": 100,
  "reasons": ["reviewer: no UTM params"]
}
```

## Sync Embedded Assets

Vercel uses embedded files from `api/assets`. After changing root `config.yaml`, `templates/`, or required `data/` files, sync them with:

```bash
./scripts/sync_vercel_assets.sh
```

## Verify

```bash
curl https://<your-vercel-domain>/healthz
curl https://<your-vercel-domain>/app
```

## Serverless Notes

- Vercel terminates HTTPS at the platform edge. Do not set `CLOAK_HTTPS_PORT`, `CLOAK_CERT_FILE`, or `CLOAK_KEY_FILE`.
- The custom JA3 listener in `cmd/cloak/main.go` is only available in standalone/container mode, not in Vercel Serverless.
- In-memory session behavior can reset across cold starts or scale-out. Basic routing, challenge cookies, template pages, and stateless request scoring still work.
