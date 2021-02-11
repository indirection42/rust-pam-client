/*!
 * Client application interface for Pluggable Authentication Modules (PAM)
 *
 * PAM is the user authentication system used in many Unix-like operating
 * systems (Linux, NetBSD, MacOS, Solaris, etc.) and handles authentication,
 * account management, session management and passwort changing via pluggable
 * modules. This allows programs (such as `login(1)` and `su(1)`) to
 * authenticate users e.g. in a Kerberos domain as well as locally in
 * `/etc/passwd`.
 *
 * This library provides a safe API to the application-faced parts of PAM,
 * covering multiple use-cases with a high grade of flexibility.
 *
 * It is currently only tested on Linux, but should also support OpenPAM-based
 * platforms like NetBSD. Solaris should also be supported, but the support
 * is untested.
 *
 * # Examples
 *
 * Sample workflow for command line interaction like `su -c`, running a
 * single program as the user after they successfully authenticated:
 *
 * ```no_run
 * use pam_client::{Context, Flag};
 * use pam_client::conv_cli::Conversation; // CLI implementation
 * use std::process::Command;
 * use std::os::unix::process::CommandExt;
 *
 * let mut context = Context::new(
 *    "my-service",       // Service name, decides which policy is used (see `/etc/pam.d`)
 *    None,               // Optional preset user name
 *    Conversation::new() // Handler for user interaction
 * ).expect("Failed to initialize PAM context");
 *
 * // Optionally set some settings
 * context.set_user_prompt(Some("Who art thou? "));
 *
 * // Authenticate the user (ask for password, 2nd-factor token, fingerprint, etc.)
 * context.authenticate(Flag::NONE).expect("Authentication failed");
 *
 * // Validate the account (is not locked, expired, etc.)
 * context.acct_mgmt(Flag::NONE).expect("Account validation failed");
 *
 * // Get resulting user name and map to a user id
 * let username = context.user();
 * let uid = 65535; // Left as an exercise to the reader
 *
 * // Open session and initialize credentials
 * let mut session = context.open_session(Flag::NONE).expect("Session opening failed");
 *
 * // Run a process in the PAM environment
 * let result = Command::new("/usr/bin/some_program")
 *                      .env_clear()
 *                      .envs(session.envlist().iter_tuples())
 *                      .uid(uid)
 *                   // .gid(...)
 *                      .status();
 *
 * // The session is automatically closed when it goes out of scope.
 * ```
 *
 * Sample workflow for non-interactive authentication
 * ```no_run
 * use pam_client::{Context, Flag};
 * use pam_client::conv_mock::Conversation; // Non-interactive implementation
 *
 * let mut context = Context::new(
 *    "my-service",  // Service name
 *    None,
 *    Conversation::with_credentials("username", "password")
 * ).expect("Failed to initialize PAM context");
 *
 * // Authenticate the user
 * context.authenticate(Flag::NONE).expect("Authentication failed");
 *
 * // Validate the account
 * context.acct_mgmt(Flag::NONE).expect("Account validation failed");
 *
 * // ...
 * ```
 *
 * Sample workflow for session management without PAM authentication:
 * ```no_run
 * use pam_client::{Context, Flag};
 * use pam_client::conv_null::Conversation; // Null implementation
 *
 * let mut context = Context::new(
 *    "my-service",     // Service name
 *    Some("username"), // Preset username
 *    Conversation::new()
 * ).expect("Failed to initialize PAM context");
 *
 * // We already authenticated the user by other means (e.g. SSH key) so we
 * // skip `context.authenticate()`.
 *
 * // Validate the account
 * context.acct_mgmt(Flag::NONE).expect("Account validation failed");
 *
 * // Open session and initialize credentials
 * let mut session = context.open_session(Flag::NONE).expect("Session opening failed");
 *
 * // ...
 *
 * // The session is automatically closed when it goes out of scope.
 * ```
 */

/***********************************************************************
 * (c) 2021 Christoph Grenz <christophg+gitorious @ grenz-bonn.de>     *
 *                                                                     *
 * This Source Code Form is subject to the terms of the Mozilla Public *
 * License, v. 2.0. If a copy of the MPL was not distributed with this *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.            *
 ***********************************************************************/

mod c_box;
mod context;
mod conversation;
mod error;
mod ffi;
mod session;
mod resp_buf;
#[cfg(feature="cli")]
pub mod conv_cli;
pub mod conv_mock;
pub mod conv_null;
pub mod env_list;

pub use context::Context;
pub use conversation::ConversationHandler;
pub use session::{Session, SessionToken};
pub use error::{Error, ErrorWith};
#[doc(no_inline)]
pub use pam_sys::types::PamReturnCode as ReturnCode;
#[doc(no_inline)]
pub use pam_sys::types::PamFlag as Flag;

/// Type alias for the result of most PAM methods.
pub type Result<T> = std::result::Result<T, Error>;
/// Type alias for the result of PAM methods that pass back a consumed struct
/// on error.
pub type ExtResult<T, P> = std::result::Result<T, ErrorWith<P>>;
