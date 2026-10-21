# Vendored dependencies

This directory contains third-party crates that are vendored (checked in) because
Wazowski needs small local modifications to them. Each crate keeps its **original
upstream license** — see the `LICENSE-APACHE` and `LICENSE-MIT` files inside each
directory. These crates are **not** covered by Wazowski's own MIT license; they
remain under their respective Apache-2.0 / MIT terms.

As required by the Apache-2.0 license (§4b), the modifications made for Wazowski
are noted below.

## `picky/` and `sspi/`

Upstream: <https://github.com/Devolutions/picky-rs> and
<https://github.com/Devolutions/sspi-rs> (dual MIT / Apache-2.0).

**Modified for Wazowski:** dependency version pins were relaxed (notably the
`curve25519-dalek` pin) so these crates build against the same crypto stack as
`russh`, resolving a version conflict. No functional/behavioural changes.

## `vnc-rs/`

Upstream: <https://github.com/HsuJv/vnc-rs> (dual MIT / Apache-2.0).

**Modified for Wazowski:** exposed `VncClient::new` and the `AuthHelper` so the
app can drive the RFB handshake itself (needed for VeNCrypt + TLS, which the
upstream crate does not implement).
