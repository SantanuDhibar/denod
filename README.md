# denod

## Deno Deploy
This service runs on Deno Deploy using `Deno.serve`. TCP proxying for the `/${XPATH}`, `/vless`, and `/ssh` endpoints is not available on Deno Deploy, so those routes return HTTP 501 there. Configure behavior via `UUID`, `SUB_PATH`, `XPATH`, `DOMAIN`, and `NAME` environment variables.

## WebSocket Endpoints
- `/vless`: VLESS over WebSocket (Basic auth `admin` / `1234`)
- `/ssh`: SSH over WebSocket proxy to `127.0.0.1:22` (Basic auth `admin` / `1234`)
