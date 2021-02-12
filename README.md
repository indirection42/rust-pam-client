# pam-client - Rust-style API to Pluggable Authentication Modules (PAM)

## Usage

1. Add the following to your Cargo.toml:
```toml
[dependencies]
pam-client = "0.1.1"
```

2. Read the crate documentation

## Functionality

The `pam-client` crate a safe API to the application-faced parts of PAM.
This includes in detail:

- PAM authentication, account validation and session management
- PAM password changing
- Three sample conversation handler implementations
- Custom conversation handlers via trait implementation
- On-the-fly switching of the conversation handler
- Suspendable RAII session handling
- Methods for refreshing and reinitialization of PAM credentials
- PAM environment list support with easy integration to `std::process::Command`
  and `nix::unistd::execve`
- Getters and setters for all standard and most Linux-specific PAM items.
- Raw access methods for non-standard PAM items
- Errors mostly convertible to `std::io::Error`

## Features

- `cli`: by default a conversation handler for command line applications is
  included. Disable this feature if you don't need it to remove a dependency
  on [`rpassword`].
 
## Supported Rust versions

The minimum supported Rust toolchain version is Rust **1.43.0**.

Currently tested up to version 1.52.0-nightly.

## Platform support

The `pam-client` crate is currently only tested on Linux, but support is
implemented for Solaris and OpenPAM-based platforms like NetBSD.

## Stability

This crate follows [semantic versioning](http://semver.org) with the additional
promise that below `1.0.0` backwards-incompatible changes will not be
introduced with only a patch-level version number change.

## Comparison with similar crates

This crate provides safe wrappers for the same library as [`pam`].
This crate aims to provide safe wrappers for different use cases at
the expense of a slightly more complex interface, while [`pam`] provides
an easier interface, but restricts the order of operations to the
most common use cases.

## License

Licensed under Mozilla Public License, Version 2.0 ([LICENSE](LICENSE)
or https://www.mozilla.org/en-US/MPL/2.0/).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, shall be licensed as above
including compatibility with secondary licenses, as defined by the MPL.

[`rpassword`]: https://crates.io/crates/rpassword
[`pam`]: https://crates.io/crates/pam
