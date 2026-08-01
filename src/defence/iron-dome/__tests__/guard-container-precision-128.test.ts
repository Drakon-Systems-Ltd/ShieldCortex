/**
 * Failing-first spec for #128 — container flags and container-scoped mutation.
 *
 * Dogfood evidence (Jarvis box, 28 Jul 2026), all three hit while setting up a
 * clean-box install test for our OWN product:
 *
 *   docker run --rm -v "$PWD/test.sh:/test.sh:ro" node:22-slim sh -c "…"
 *     → blocked as `file-delete`, matched "rm". `--rm` removes the CONTAINER on
 *       exit; nothing on the host is touched.
 *   docker run … sh -c "apt-get install -y git python3 make g++"
 *     → blocked as `install-package`. The install happens inside an EPHEMERAL
 *       container. Host mutation is the thing that rule exists to gate.
 *
 * The precision rule: a dash-flag token is never a command, and a package
 * install confined to a throwaway container is not host mutation.
 *
 * The safety rule, which outranks it: a container can be a host-mutation
 * vehicle. `--privileged`, a host bind-mount, a host namespace, or a
 * chroot/nsenter in the inner command all mean the container boundary is not a
 * boundary. Ambiguity keeps the gate — every one of those still gates exactly
 * as before, and that is what the second half of this file pins.
 */
import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

const decide = (command: string) => evaluateToolCall('Bash', { command });

describe('#128 — a dash-flag is not the delete command', () => {
  it("docker's --rm container-cleanup flag is not a file delete", () => {
    const v = decide('docker run --rm -v "$PWD/test.sh:/test.sh:ro" node:22-slim sh -c "node /test.sh"');
    expect(v.signals ?? []).not.toContain('file-delete');
    expect(v.decision).toBe('allow');
  });

  it('the short -rm form is likewise not a delete', () => {
    const v = decide('somecmd -rm build');
    expect(v.signals ?? []).not.toContain('file-delete');
  });

  it('podman --rm gets the same treatment', () => {
    const v = decide('podman run --rm alpine echo hi');
    expect(v.signals ?? []).not.toContain('file-delete');
  });

  // ── the gate must still fire on the real thing ──

  it('a real rm still gates', () => {
    expect((decide('rm /tmp/scratch.log').signals ?? [])).toContain('file-delete');
  });

  it('a real rm INSIDE a container command still gates', () => {
    // The flag is inert; the inner command is not.
    expect((decide('docker run --rm alpine rm /etc/passwd').signals ?? [])).toContain('file-delete');
  });

  it('rm -rf on a host path is still catastrophic even alongside --rm', () => {
    const v = decide('docker run --rm -v /:/host alpine rm -rf /host/etc');
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
  });

  it('sudo rm and piped xargs rm still gate', () => {
    expect((decide('sudo rm /var/log/syslog').signals ?? [])).toContain('file-delete');
    expect((decide('find . -name "*.tmp" | xargs rm').signals ?? [])).toContain('file-delete');
  });
});

describe('#128 — a package install confined to a throwaway container is not host mutation', () => {
  it('apt-get install inside a plain container run does not gate as host install', () => {
    const v = decide('docker run --rm node:22-slim sh -c "apt-get update -qq; apt-get install -y -qq git python3 make g++"');
    expect(v.signals ?? []).not.toContain('install-package');
    expect(v.decision).toBe('allow');
  });

  it('the same for podman and for a --volume-mounted project dir', () => {
    const v = decide('podman run --rm -v "$PWD:/work:ro" debian:12 sh -c "apt-get install -y curl"');
    expect(v.signals ?? []).not.toContain('install-package');
  });

  // ── the container boundary must be a real boundary, or the gate stays ──

  it('KEEPS the gate when the container is privileged', () => {
    const v = decide('docker run --privileged --rm alpine sh -c "apt-get install -y evil"');
    expect(v.signals ?? []).toContain('install-package');
  });

  it('KEEPS the gate when the host filesystem root is bind-mounted', () => {
    const v = decide('docker run --rm -v /:/host alpine sh -c "apt-get install -y evil"');
    expect(v.signals ?? []).toContain('install-package');
  });

  it('KEEPS the gate when the inner command chroots or nsenters to the host', () => {
    expect((decide('docker run --rm -v /:/host alpine chroot /host apt-get install -y evil').signals ?? []))
      .toContain('install-package');
    expect((decide('docker run --rm --pid=host alpine nsenter -t 1 -m apt-get install -y evil').signals ?? []))
      .toContain('install-package');
  });

  it('KEEPS the gate when a host namespace is shared', () => {
    expect((decide('docker run --rm --net=host alpine sh -c "apt-get install -y evil"').signals ?? []))
      .toContain('install-package');
  });

  it('KEEPS the gate for a plain host install with no container in sight', () => {
    expect((decide('apt-get install -y backdoor').signals ?? [])).toContain('install-package');
    expect((decide('sudo apt install nginx').signals ?? [])).toContain('install-package');
  });

  it('KEEPS the global-npm gate — that rule is about the host toolchain', () => {
    expect((decide('npm i -g evil-pkg').signals ?? [])).toContain('install-package-global');
  });

  it('does not treat a bare mention of docker as a container context', () => {
    // The downgrade must require an actual container RUN, not the word.
    expect((decide('echo "use docker run --rm"; apt-get install -y evil').signals ?? []))
      .toContain('install-package');
  });
});
