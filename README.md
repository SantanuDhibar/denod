# denod

## Deno Deploy
This service runs on Deno Deploy using `Deno.serve`. TCP proxying for the `/${XPATH}` endpoints is not available on Deno Deploy, so those routes return HTTP 501 there. Configure behavior via `UUID`, `SUB_PATH`, `XPATH`, `DOMAIN`, and `NAME` environment variables.
