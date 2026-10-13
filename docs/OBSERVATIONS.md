# Read-only policy observations

The helper optionally accepts a third systemd activation descriptor named
`observations`. Its root-owned configuration supplies `observer_uid` and
`observations_socket` together. The observer UID must be non-root and different
from both the directory writer and aggregate operator. Existing two-descriptor
configurations retain their original behavior.

The framed Unix protocol accepts only a schema version 1 `observations` request
with `generation` and `offset`. The first page may use an empty generation and
zero offset; subsequent pages must carry the returned generation. A changed
generation requires restarting the read. Requests are limited to 512 bytes,
responses to 512 KiB and the connection deadline to two seconds. The cached
catalog is capped at 4,096 grants and 8 MiB. Truncation sets `complete: false`.

The response exposes logical group/rule contributors and revisions, qualified
binding references, original observation/ownership times and grant deadlines.
It excludes raw directory records, credentials and operator reason text. The
immutable cache is copied after successful engine processing. Reading it does
not acquire the enforcement gate, sample the enforcement clock, touch durable
state or call the firewall. Failure of the observation transport does not stop
the enforcement listeners.

Compilation evidence is separate from installation. Consumers must join the
writer sequence, floor hash, compilation time and independently observed kernel
membership. Expiry alone cannot confirm removal. Shared counters cannot prove a
particular device matched a rule. This endpoint does not enroll devices or
change the existing managed cohort.

Race-enabled tests cover immutable reads while the enforcement gate is held,
unchanged deadlines and side-effect traces, generation changes, strict request
parsing, actual Unix peer-UID rejection and mutation-shaped requests. Appliance
qualification must additionally exercise the three-descriptor supervisor and
forwarding under repeated observation load.
