# VPN Node

VPN node agent and deployment tools for [Undercore Orchestrator](https://github.com/UndercoreCo/orchestrator).

**Status: repository preparation.** The existing Undercore Amnezia-agent is being
prepared for extraction into this project. Runtime source and an installer are
not available here yet. There is currently no installation command to run.

The planned first supported stack is AmneziaWG 3.1. This project will provide
node-side API, peer lifecycle management, and deployment/update tooling. The
orchestrator remains responsible for selecting nodes and maintaining assignments;
the caller's backend remains responsible for user authorization and entitlement.

See the [roadmap](https://github.com/UndercoreCo/orchestrator/blob/main/docs/public/roadmap.md)
for the extraction and provisioning stages.

## License

Project-owned code and documentation use the [MIT license](LICENSE).
External VPN engines and dependencies retain their own licenses.
