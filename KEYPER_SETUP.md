# Running a Keyper

For a single independent keyper operator — you hold only your own
private key. The chain RPC, the deployed `Election` contract, and every
other keyper are external to this stack.

Everything here uses two files at the project root:
`.env.keyper.example` (template) and `docker-compose.keyper.yml`.

## Prerequisites

- Docker, with `docker compose` (v2).
- Your own Ethereum private key, already registered as a member of the
  on-chain `KeyperSet` for this election (the election administrator adds
  it — ask them to confirm before you start).
- A chain RPC URL you can reach.
- (For a real, authenticated deployment) the election administrator's
  `COORDINATOR_ADDRESS` — they generate this once and give it to you
  out of band.

## 1. Configure

```sh
cp .env.keyper.example .env
```

Edit `.env`:

| Variable              | Required? | What to put |
| ---------------------- | --------- | ----------- |
| `KEYPER_PRIVATE_KEY`   | Yes       | Your keyper's private key. Keep this secret. |
| `RPC_URL`              | Yes       | Chain RPC URL. |
| `KEYPER_PORT`          | No        | Port to listen on / publish to the host. Default `5001`. |
| `COORDINATOR_ADDRESS`  | For real deployments | The administrator's address. Needed for bootstrapping keyper and authenticating endpoints. Otherwise enforces **no auth at all** on its endpoints. |
| `KEYPER_STATE_DIR_HOST`| No        | Host-side path for this keyper's encrypted state. Default `./keyper-state`. Only matters if you're running more than one keyper instance on the same machine (local testing) — give each its own path, or they'll silently overwrite each other's state. |

There is nothing else to set. The election
administrator's coordinator figures out your DKG index on its own, from
the on-chain `KeyperSet` (matching the address your `KEYPER_PRIVATE_KEY`
derives to), the first time DKG runs.

## 2. Start it

```sh
mkdir -p keyper-state
docker compose -f docker-compose.keyper.yml up -d --build
```

`keyper-state/` is a bind-mounted volume holding this keyper's encrypted
state (DKG secret, bootstrap tokens, bootstrap keypair). Keep it around —
losing it means losing this keyper's ability to ever decrypt for this
election again (see "Restarting" below).

## 3. Verify

```sh
curl -s http://127.0.0.1:${KEYPER_PORT:-5001}/status | python3 -m json.tool
```

- `address` should match the key you registered with the administrator.
- `bootstrapped` starts `false` and flips to `true` once the
  administrator's coordinator reaches you and pushes your bearer tokens.
- `keyper_id` is `null` until DKG actually runs.

## 4. Onboarding — what to give the administrator

Just your keyper's public URL (`http://<your-host>:<KEYPER_PORT>`), once,
out of band. That's the only thing they need from you. There is no token
for you to generate or exchange — the administrator's `dkg-coordinator`
mints your bearer tokens itself and pushes them to you automatically over
an encrypted, signed channel the moment it can reach your `/status`.

From here everything is automatic on your end: the administrator's stack
bootstraps your tokens, runs DKG across all keypers, and — once voting
closes — triggers your decryption-share submission. You don't run any
commands for any of that; just keep this container up.

## Restarting

Safe at any time. On restart this keyper reloads its encrypted state from
`keyper-state/` — DKG secret, resolved index, and bootstrap tokens all
come back exactly as they were, so a restart never triggers a fresh DKG
ceremony or a fresh bootstrap. This requires:
- the same `keyper-state/` directory (don't delete it),
- the same `KEYPER_PRIVATE_KEY` (state is encrypted with a key derived
  from it — a different key can't decrypt it).

If both of those hold, a restart is invisible to everyone else.

## Tear down

```sh
docker compose -f docker-compose.keyper.yml down
```

`keyper-state/` is left on disk — remove it yourself (`rm -rf keyper-state`)
only if you're certain you're done with this election; there's no way to
recover a lost DKG secret.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `/status.bootstrapped` stays `false` | The administrator's coordinator can't reach your public URL yet, or hasn't run. Confirm the URL you gave them is correct and reachable from their side. |
| `Unauthorized` on any endpoint | `COORDINATOR_ADDRESS` in your `.env` doesn't match the address behind the administrator's `COORDINATOR_SIGNING_KEY`, or you were never successfully bootstrapped. Check `/status.bootstrapped`. |
| Container can't reach `RPC_URL` | If the chain is on this same machine, use `http://host.docker.internal:8545`, not `127.0.0.1` — `127.0.0.1` inside the container means the container itself, not your host. |
| Running more than one keyper on the same machine (local testing only) | Give each instance its own `KEYPER_PORT`, its own `KEYPER_STATE_DIR_HOST`, and its own compose project name (`docker compose -p keyper2 -f docker-compose.keyper.yml ...`), or they'll silently overwrite each other's state. |
