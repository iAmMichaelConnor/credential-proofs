//! Shared World ID utilities: `binding` (context-bound statements),
//! `certificate` (v6 recursive certificate checks), `signal` (the exact
//! 224-byte signal encoding) and `schema` (all three under one module). No
//! inner-verifier dependency; policy checks and host parsing verify no proof.
//! See `docs/world-id.md`.
pub mod binding;
pub mod certificate;
pub mod schema;
pub mod signal;
