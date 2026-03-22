# Cloud Server Quickstart

Use this path when you want always-on Linux servers, remote boxes, or cloud VMs to stay connected to your ShieldCortex Cloud account.

The important distinction is:

- machine uptime is not enough
- ShieldCortex Cloud marks a device **online** only when it receives a recent ShieldCortex heartbeat

## What you need on each server

1. ShieldCortex `3.4.29` or newer
2. a Team or higher licence key
3. a cloud API key with sync access
4. the persistent headless worker service

> [!IMPORTANT]
> The automatic 14-day Pro trial does **not** unlock cloud sync. Servers still need a Team or higher licence to appear in ShieldCortex Cloud and stay online there.

## Install

```bash
npm install -g shieldcortex@latest
```

## Connect the server to your account

```bash
shieldcortex license activate <team-key>
shieldcortex config --cloud-api-key <cloud-api-key>
shieldcortex config --cloud-enable
shieldcortex service install --headless
```

If you already installed the service on an older version, rebuild it:

```bash
shieldcortex service repair --headless
```

## Verify

```bash
shieldcortex --version
shieldcortex license status
shieldcortex config --cloud-status
shieldcortex service status
```

You want to see:

- `Tier: Team` or higher
- `Cloud Enabled: Yes`
- API key present
- `Mode: worker`
- `Running: yes`

If you manage keys in ShieldCortex Cloud, remember that keys are scope-based. A valid Team licence is necessary but not sufficient on its own if the selected key cannot access the required cloud surfaces.

## Linux note

On headless Ubuntu or other Linux servers, keep the user service alive without an interactive login:

```bash
sudo loginctl enable-linger <user>
```

ShieldCortex tries to enable linger during `service install --headless`, but some environments require running that command explicitly.

## Troubleshooting

### Device still shows offline in ShieldCortex Cloud

Usually one of these is true:

- the server is still on the Free tier
- cloud sync is disabled locally
- the cloud API key was never configured
- the old dashboard-style service is still installed instead of the worker

Check:

```bash
shieldcortex license status
shieldcortex config --cloud-status
shieldcortex service status
```

### Device is running but cloud still says stale

Wait a few minutes. The cloud UI depends on heartbeat time, not immediate registration.

### Service says running but nothing reaches cloud

That almost always means the service is alive but ShieldCortex is not enrolled in your account yet. Re-check licence and cloud config first, not systemd.
