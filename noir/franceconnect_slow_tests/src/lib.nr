//! End-to-end known-answer tests of franceconnect. Each verifies a complete signed token
//! of up to 2048 base64 bytes (several minutes and GB per test), so they live
//! apart from the package's fast tests.
mod known_answer_tests;
