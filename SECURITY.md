# Security

This project is under development. The offline checker does not modify a firewall. Do not use its shadow decisions as a production enforcement mechanism until the runtime and packet-level [activation gates](docs/architecture.md#implementation-gates) pass.

Directory-managed rules are a bounded authorization input. They cannot change the router's Security policy, protected endpoints, translator maps, runtime commands, credentials or kernel hooks. A root-owned baseline still requires review: the software cannot discover every administration endpoint or retained restriction in an unfamiliar deployment.

Keep directory bind secrets, RADIUS client secrets, bindings, protected inventories and operational logs outside this public repository. Production directory access must verify the TLS certificate chain and hostname, with no plaintext or verification-disabled fallback. Use a scoped read account; never a directory administrator token. No controller credentials or controller API integration are required.

Report suspected vulnerabilities through this repository's private GitHub security reporting when available. Otherwise contact the repository owner privately before opening an issue containing deployment details, credentials or an exploit. Public issues and test fixtures must use synthetic data.
