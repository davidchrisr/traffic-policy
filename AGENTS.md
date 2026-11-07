# Agent Notes

- Run repository code in a tooling container or a
  [development stack](dev/docker/README.md), not on the host.
- Unit tests do not reach the gateway's kernel paths or the browser. Verify
  changes there end to end with [Verification](docs/VERIFICATION.md); the
  development stack does not cover the production install, which
  [Setup](docs/SETUP.md) describes.
