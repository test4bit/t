# vpn-runner (AWG 3.1)

Linux client and GitHub Actions server; WARP uses standard WireGuard. The binary `vpn` is built from the included source with `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o vpn ./cmd/vpn` (linux/amd64). Both client and runner must use the same AWG settings.

## WARP endpoint control

The WARP server accepts only restricted SSH exec commands at `192.168.166.1:2222` over the VPN. Set repository Actions secrets `WARP_SSH_HOST_KEY` (unencrypted OpenSSH private host key; use the same key across runner instances) and `WARP_SSH_PASSWORD` (at least 16 bytes, randomly generated). The workflow already passes them to the server. No public SSH listener, shell, PTY or forwarding is provided. User is `warp`.

Pin the host public key in your client known_hosts under the alias `vpn-runner` (verify its fingerprint out of band). From the client namespace:

```sh
sudo ip netns exec amnezia ssh -T -p 2222 \
  -o HostKeyAlias=vpn-runner -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/absolute/path/to/vpn-runner-known_hosts \
  warp@192.168.166.1 status
# replace status with: 'set 188.114.97.10:2408'
```

`set` only accepts an IPv4:port in the explicitly permitted Cloudflare WARP pools; it applies without restarting AWG. It does not verify the target and does not roll back. Changing to an unreachable endpoint interrupts WARP traffic until another is chosen; rotation resets the choice.

## Optional warpscout

Set repository Actions variable `ENABLE_WARP_SCOUT` to `true` to install pinned warpscout and create a temporary account during each runner start. Then execute SSH command `scan`: it scans with WireGuard from the runner's host network and applies the selected WARP endpoint. This needs Go 1.26.3+ (automatic toolchain download), network access and successful Cloudflare registration; the scan uses a separate WARP account and doesn't guarantee the endpoint works for the active account. It may take minutes. No country-selection or rollback is implemented.

## Security and operation

Keep `GH_PAT` in the Actions secret and the client environment, never in source. `RandomTrailers` is enabled on both AWG ends, with equal S1-S4 and a per-run header protection key. `DisableCookies` is enabled only for the client, which removes handshake flood protection there. The separate WARP peer retains plain WireGuard defaults. Client health checks and scheduled rotations may terminate an interrupted session.
