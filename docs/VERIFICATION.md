# Verification

These recipes use the [development stack](../dev/docker/README.md). Run the
commands from `dev/docker/` with the env file for the stack being checked. The
examples use `.env.development`; substitute your filename:

```sh
stack_env=.env.development
```

## Start and check readiness

[Configure](../dev/docker/README.md#configure-a-stack) and
[start](../dev/docker/README.md#start) the stack. After changing source, rebuild
and restart it as the README describes; a running stack keeps the old build.

```sh
nerdctl compose --env-file "$stack_env" ps -a
nerdctl compose --env-file "$stack_env" logs gateway | grep '"ready":true'
nerdctl compose --env-file "$stack_env" exec controller /src/dev/docker/inspect.sh status
```

The stack is ready when the ordered build and init commands returned status 0,
the three runtime services are running, the gateway log shows `"ready":true` for
both `enforcement` and `gateway`, and `status` reports equal `desired` and
`applied` revisions, a null `lastError`, and no `activeConditions`. The one-off
build and init containers are removed after they exit. `inspect.sh` also prints
`conditions`, `instances`, and `requests`.

## Drive it and keep evidence

Use the browser at `TP_ORIGIN` as Admin, and generate traffic from the client:

```sh
nerdctl compose --env-file "$stack_env" exec client curl -s -m 3 -o /dev/null http://1.1.1.1/
nerdctl compose --env-file "$stack_env" exec client dig +time=2 +tries=1 example.com
```

For each check, keep a screenshot of the result in the browser and a second
observation of the same effect: `inspect.sh` output, the gateway log, or the
gateway's nftables table. Save evidence outside the stack's volumes, since
`down -v` removes them.

## Recipes

- **Unregistered host becomes a Request.** On a fresh stack, send client
  traffic. `inspect.sh requests` lists `TP_CLIENT_ADDRESS`, and Requests shows
  it with the name Suricata saw in the client's lookup.
- **Registration applies rules.** Register `TP_CLIENT_ADDRESS` from Requests, or
  add it in Settings, then send traffic again. `inspect.sh instances` shows the
  instance with a controller-assigned id, and Monitor's inspector for it lists
  the packets the outgoing catch-all blocked, by service.
- **Rule ports reach nftables.** Add a rule with ports such as `443-1000, 321`
  for the client's instance. The gateway's table holds the set once
  `inspect.sh status` shows the new revision applied:
  `nerdctl compose --env-file "$stack_env" exec gateway nft list table inet traffic_policy | grep proto-dst`.
- **Unreadable saved policy file.** Write an invalid file as the gateway's
  account, then restart the gateway:

  ```sh
  nerdctl compose --env-file "$stack_env" exec gateway setpriv --reuid=traffic-policy \
    --regid=traffic-policy --init-groups \
    sh -c 'umask 077; printf "{" >/var/lib/traffic-policy/gateway/policy-apply.json'
  nerdctl compose --env-file "$stack_env" restart gateway
  ```

  The gateway logs `"step":"intent-read"`, renames the file to
  `policy-apply.json.unreadable-<UTC time>`, and comes up ready;
  `inspect.sh conditions` shows `gateway_intent_unreadable` recovered, with one
  more occurrence than before, and History → System status lists it.

- **Capped DNS receive buffer.** Set `TP_DNS_RECEIVE_BUFFER_BYTES` above the
  host's `net.core.rmem_max` (read it in the gateway from
  `/proc/sys/net/core/rmem_max`) and run `up -d gateway`. The gateway logs
  `"step":"receive-buffer"` and stays ready, and `dns_receive_buffer` is active
  until a restart with a size that fits.

## Verification limits

- Write service-owned state as `traffic-policy` using `setpriv`, as in the
  saved-policy recipe. The stack intentionally drops `CAP_DAC_OVERRIDE` from
  root's capabilities.
- Use a fresh stack for checks that depend on first-run behavior. Restarts
  preserve its volumes.
- The client routes through the gateway. Verify the actual packet path and
  isolation under the runtime in use; the Compose network's `internal` setting
  alone does not establish isolation.

## Clean up

See [Stop](../dev/docker/README.md#stop) for shutdown and volume removal.
