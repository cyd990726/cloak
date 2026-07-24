# Fly.io Deployment

This directory is the Fly.io application root.

## Files

- `Dockerfile` builds the Go service and packages `config.yaml`, `templates/`, and `data/`.
- `fly.toml` configures Fly's HTTP service on internal port `8080`.
- `/healthz` is used by Fly health checks and does not run traffic scoring.

## First Deploy

Install and log in to the Fly CLI:

```bash
brew install flyctl
fly auth login
```

Choose a globally unique app name, then edit `fly.toml`:

```toml
app = "your-unique-app-name"
```

Create the Fly app:

```bash
cd "/Users/bytedance/Desktop/recognition/流量识别后端"
fly apps create your-unique-app-name
```

Set a production secret key:

```bash
fly secrets set CLOAK_SECRET_KEY="$(openssl rand -hex 32)"
```

Deploy:

```bash
fly deploy
```

## Verify

```bash
fly status
fly logs
curl https://your-unique-app-name.fly.dev/healthz
curl https://your-unique-app-name.fly.dev/app
```

## Runtime Environment Overrides

The service reads `config.yaml` first, then allows these environment variables to override runtime settings:

- `CLOAK_HOST` or `SERVER_HOST`
- `CLOAK_PORT` or `PORT`
- `CLOAK_SECRET_KEY` or `SECRET_KEY`
- `CLOAK_COUNTRY_DB` or `COUNTRY_DB`
- `CLOAK_HTTPS_PORT` or `HTTPS_PORT`
- `CLOAK_CERT_FILE`
- `CLOAK_KEY_FILE`

The default country database path is `data/BIT4BF5.tmp`. Despite the temporary-looking filename, it is a GeoLite2 Country database in the current checkout. Replace it with a clearly named MaxMind Country or City database when you rotate GeoIP data.

Fly terminates HTTPS at the edge for this HTTP deployment, so the app itself listens on plain HTTP port `8080`.
