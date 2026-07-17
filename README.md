What is Eauth?
==============

https://eauth.us.to/ - Your #1 software login and authentication system, providing you with the most secure, flexible, and easy-to-use solutions.

Functions
-------------

```rust
fn init_request()
```
```rust
fn login_request(username: &str, password: &str)
```
```rust
fn register_request(username: &str, password: &str, key: &str)
```
```rust
fn hardware_reset_request(username: &str)
```

Configuration
-------------

Navigate to `eauth.rs`, and fill these lines of code:

```rust
// ---- Required configuration ----
const APPLICATION_TOKEN: &str = "application_token_here";
const APPLICATION_SECRET: &str = "application_secret_here";
const APPLICATION_VERSION: &str = "application_version_here";
```
