# Experimental deployment and security notes

These technical notes describe the current interfaces. They do not authorise a
production deployment; the deployment freeze remains in force.

### Install and first run

The normal installer installs `upt`, `upt-web`, and `upt-agent` but does not
start or deploy a service. For the example systemd units, first create the
restricted service identity and grant it only the separate web state/config/
socket access (the agent remains the only process with Docker access):

```bash
systemd-sysusers systemd/upt-web.sysusers.example
install -d -o docker-update-manager-web -g docker-update-manager-web -m 0700 /var/lib/docker-update-manager-web
chown root:docker-update-manager-web /etc/docker-update-manager/web.yml
chmod 0640 /etc/docker-update-manager/web.yml
```

The agent unit deliberately keeps home directories read-only
(`ProtectHome=read-only`) and system paths protected
(`ProtectSystem=full`). Web digest-pin advancement and web rollback must
atomically replace their selected Compose source files, so each project source
directory must be explicitly authorised in the agent's systemd sandbox. Before
those actions, the agent performs a temporary-file create/remove capability
check in every source directory it will replace; it does not modify a Compose
file during this check. Mutable-tag web updates that do not edit Compose are
not blocked by this requirement.

For the example `/root/compose-example` project, install a narrow operator-managed
drop-in (inspect `systemctl cat upt-agent` first if the unit name or source
directory differs):

```bash
install -d -m 0755 /etc/systemd/system/upt-agent.service.d
install -m 0644 systemd/upt-agent.compose-writes.conf.example \
  /etc/systemd/system/upt-agent.service.d/compose-writes.conf
systemctl daemon-reload
systemctl restart upt-agent
```

The checked-in example contains only `ReadWritePaths=/root/compose-example`. Edit the
drop-in before applying it if that is not the exact reviewed project directory;
add separate entries only for other explicitly approved Compose source
directories. This grants the agent OS-level write access throughout each named
directory because atomic replacement needs write permission on its parent.
Never use `ReadWritePaths=/root`, `/home`, `/etc`, or `/` for convenience.
Changing the sandbox requires both `systemctl daemon-reload` and restarting
`upt-agent`; UPT never applies the drop-in or restarts the service itself. CLI
commands run as the host operator outside this service namespace and therefore
have different filesystem permissions from browser-triggered agent operations.
The agent's create/remove preflight is authoritative: do not assume a drop-in is
effective from its text or host-side ownership/mode bits alone. If the web action
still reports denied source access after an operator restart, keep the protection
in place and diagnose the effective agent mount namespace rather than granting a
broader root.

Now create the one-time setup credential through the host CLI:

```bash
upt web bootstrap
# copy the displayed code; it is shown once and expires shortly
```

Run the agent and web service using the example units in
`systemd/upt-agent.service.example` and `systemd/upt-web.service.example`, or
run `upt-agent` and `upt-web` under an equivalent restricted service manager.
Then open the configured listen address and create the administrator using the
setup code. There are no default credentials. Recovery is host-driven:

```bash
upt web reset-admin
# then apply it interactively; both code and password are prompted securely
upt web reset-admin --apply
upt web status
```

Web-boundary settings are authoritative in `/etc/docker-update-manager/web.yml`; both `upt-web`, `upt-agent`, and `upt web ...` read the shared socket setting there. A legacy `web:` block left in `config.yml` is ignored with a warning so upgrades keep working; move those settings to `web.yml`. The main file remains authoritative only for core CLI/agent behaviour.

### Upgrading: web and agent version agreement

`upt`, `upt-web` and `upt-agent` are one release with one version
(`docs/versioning.md`). `install.sh` installs all three from the same checkout
into one virtual environment, but it does not restart running services: a
running `upt-web` or `upt-agent` keeps its previous code until the operator
restarts it. After installing a new UPT release, restart both services:

```bash
systemctl restart upt-agent upt-web
upt web status   # expect "Version status: versions match"
```

While the web and agent versions differ, or the agent reports no version
(for example, an agent from before 0.4.0), the web interface stays readable and
Settings/Overview show the mismatch. Every browser-triggered mutation (update,
rollback, Compose Apply/Discard/trust) is refused with "UPT web and agent
versions do not match. Complete the UPT upgrade before making changes."
`upt web status` exits `20` in that state; `upt doctor` reports the running
agent version and agreement (and reports an unreachable agent separately). UPT never restarts or upgrades either
component itself to repair a mismatch.

The privileged agent keeps Docker/update history and cached scan state in the
existing UPT SQLite database under `/var/lib/docker-update-manager`. The
unprivileged web service stores administrator credentials, sessions, and its web
audit records separately under `/var/lib/docker-update-manager-web`; it never
needs read access to root-owned UPT config/state. Migrations preserve history,
rollback references, protected images, and disk snapshots. For safety, bootstrap
and recovery only accept this managed web-state tree (or a subdirectory); the
installer rejects unrelated state paths rather than chowning arbitrary files.

### Reverse proxy and security

Bind the web service to loopback by default. A non-loopback HTTP bind is refused
unless `web.allow_insecure_http: true` is explicitly set. A trusted proxy does
not make direct plain-HTTP access safe; use TLS at the proxy and keep the UPT
listener private. For NGINX Proxy Manager, proxy a
dedicated host to the configured UPT web port and enable TLS; configure
`web.allowed_hosts` with the public hostname and forward `Host`,
`X-Forwarded-For`, and `X-Forwarded-Proto` only from the trusted proxy. UPT uses
forwarded HTTPS/client-IP information only when the connecting peer matches
`web.trusted_proxies`, and rejects forwarding entirely from any other address.
When the peer is trusted, the `X-Forwarded-For` chain is parsed as IP addresses
only and walked from the nearest hop towards the client, stopping at the first
address that is not a configured trusted proxy; a client-supplied leading entry
therefore cannot spoof the audit or login-throttle identity. `X-Forwarded-Proto`
is read from the nearest (right-most) value, so `Secure` cookies and HSTS follow
HTTPS termination by a trusted proxy only. Malformed forwarding values are
ignored and the direct peer is retained. This assumes the proxy appends or
overwrites the forwarding headers. `trusted_proxies` must list proxy addresses or
networks only: catch-all entries such as `0.0.0.0/0` and `::/0` are refused, and
chains longer than 20 entries keep the nearest hops so padding the header cannot
discard the address the proxy reported. UPT does not support arbitrary subpath mounting in
Phase 1. Do not expose the service directly to the public internet.
