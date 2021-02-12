//! PAM sessions and related structs

/***********************************************************************
 * (c) 2021 Christoph Grenz <christophg+gitorious @ grenz-bonn.de>     *
 *                                                                     *
 * This Source Code Form is subject to the terms of the Mozilla Public *
 * License, v. 2.0. If a copy of the MPL was not distributed with this *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.            *
 ***********************************************************************/

use crate::Context;
use crate::ConversationHandler;
use crate::env_list::EnvList;
use crate::{Result, ExtResult, Flag};

use pam_sys::wrapped::{setcred, close_session};

/// Token type to resume RAII handling of a session that was released with [`Session::leak()`].
///
/// The representation may not yet be stable, so don't rely on it.
#[derive(Debug,Clone,Copy)]
#[must_use]
pub enum SessionToken {
	FullSession,
	PseudoSession
}

/// An active PAM session or pseudo session
#[must_use]
pub struct Session<'a, ConvT> where ConvT: ConversationHandler {
	context: &'a mut Context<ConvT>,
	session_active: bool,
	credentials_active: bool
}

impl<'a, ConvT> Session<'a, ConvT> where ConvT: ConversationHandler {
	/// Constructs a `Session` object for a PAM context.
	pub(crate) fn new(context: &'a mut Context<ConvT>, real: bool) -> Session<'a, ConvT> {
		Self {
			context,
			session_active: real,
			credentials_active: true
		}
	}

	/// Extends the lifetime of existing credentials.
	///
	/// Might be called periodically for long running sessions to
	/// keep e.g. Kerberos tokens alive.
	///
	/// Because of limitations in [`pam_sys`] the flags are currently ignored.
	/// Use [`Flag::NONE`] or [`Flag::SILENT`].
	///
	/// # Errors
	/// Expected error codes include:
	/// - `ReturnCode::BUF_ERR`: Memory allocation error
	/// - `ReturnCode::CRED_ERR`: Setting credentials failed
	/// - `ReturnCode::CRED_EXPIRED`: Credentials are expired
	/// - `ReturnCode::CRED_UNAVAIL`: Failed to retrieve credentials
	/// - `ReturnCode::SYSTEM_ERR`: Other system error
	/// - `ReturnCode::USER_UNKNOWN`: User not known
	pub fn refresh_credentials(&mut self, _flags: Flag) -> Result<()> {
		self.context.wrap_pam_return(setcred(self.context.handle(), Flag::REFRESH_CRED/*|flags*/))
	}

	/// Fully reinitializes the user's credentials.
	///
	/// Because of limitations in [`pam_sys`] the flags are currently ignored.
	/// Use [`Flag::NONE`] or [`Flag::SILENT`].
	///
	/// See [`Context::reinitialize_credentials()`] for more information.
	pub fn reinitialize_credentials(&mut self, _flags: Flag) -> Result<()> {
		self.context.wrap_pam_return(setcred(self.context.handle(), Flag::REINITIALIZE_CRED/*|flags*/))
	}

	/// Converts the session into a [`SessionToken`] without closing it.
	///
	/// The returned token can be used to resume handling the
	/// session with [`Context::unleak_session()`].
	///
	/// Please note, that if the session isn't closed eventually and the
	/// established credentials aren't deleted, security problems might
	/// occur.
	///
	/// Depending on the platform it may be possible to close the session
	/// from another context than the one that started the session. But as
	/// this behaviour cannot be safely relied upon, it is recommended to
	/// close the session within the same PAM context.
	pub fn leak(mut self) -> SessionToken {
		let result = if self.session_active { SessionToken::FullSession } else { SessionToken::PseudoSession };
		self.session_active = false;
		self.credentials_active = false;
		result
	}

	/// Returns the value of a PAM environment variable.
	///
	/// See [`Context::getenv()`].
	#[rustversion::attr(since(1.48), doc(alias = "pam_getenv"))]
	pub fn getenv<'b>(&'b self, name: &str) -> Option<&'b str> {
		self.context.getenv(name)
	}

	/// Sets or unsets a PAM environment variable.
	///
	/// See [`Context::putenv()`].
	#[rustversion::attr(since(1.48), doc(alias = "pam_putenv"))]
	pub fn putenv(&mut self, name_value: &str) -> Result<()> {
		self.context.putenv(name_value)
	}

	/// Returns a copy of the PAM environment in this context.
	///
	/// See [`Context::envlist()`].
	#[rustversion::attr(since(1.48), doc(alias = "pam_getenvlist"))]
	pub fn envlist(&self) -> EnvList {
		self.context.envlist()
	}

	/// Manually closes the session
	///
	/// Closes the PAM session and deletes credentials established when opening
	/// the session. Session closing happens automatically when dropping
	/// the session, so this is not strictly required.
	///
	/// Please note that the application must usually have the same privileges
	/// to close as it had to open the session (e.g. have EUID 0).
	///
	/// Relevant `flags` are [`Flag::NONE`] and [`Flag::SILENT`]
	///
	/// # Errors
	///
	/// Expected error codes include:
	/// - `ReturnCode::ABORT`: Generic failure
	/// - `ReturnCode::BUF_ERR`: Memory allocation error
	/// - `ReturnCode::SESSION_ERR`: Generic session failure
	/// - `ReturnCode::CRED_ERR`: Deleting credentials failed
	/// - `ReturnCode::SYSTEM_ERR`: Other system error
	///
	/// The ownership of `self` is passed back in the error payload.
	/// On drop the session will once again try to close itself.
	#[rustversion::attr(since(1.48), doc(alias = "pam_close_session"))]
	pub fn close(mut self, flags: Flag) -> ExtResult<(), Self> {
		if self.session_active {
			let status = close_session(self.context.handle(), flags);
			if let Err(e) = self.context.wrap_pam_return(status) {
				return Err(e.into_with_payload(self));
			}
			self.session_active = false;
		}
		if self.credentials_active {
			let status = setcred(self.context.handle(), Flag::DELETE_CRED/*|flags*/);
			if let Err(e) = self.context.wrap_pam_return(status) {
				return Err(e.into_with_payload(self));
			}
			self.credentials_active = false;
		}
		Ok(())
	}
}

/// Destructor ending the PAM session and deleting established credentials
impl<'a, ConvT> Drop for Session<'a, ConvT> where ConvT: ConversationHandler {
	fn drop(&mut self) {
		if self.session_active {
			let status = close_session(self.context.handle(), Flag::NONE);
			self.session_active = false;
			let _ = self.context.wrap_pam_return(status);
		}
		if self.credentials_active {
			let status = setcred(self.context.handle(), Flag::DELETE_CRED/*|Flag::SILENT*/);
			self.credentials_active = false;
			let _ = self.context.wrap_pam_return(status);
		}
	}
}


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_token() {
		let token = SessionToken::FullSession;

		let mut context = Context::new(
			"test",
			Some("user"),
			crate::conv_null::Conversation::default()
		).unwrap();
		let session = context.unleak_session(token);
		let _ = session.leak();
	}

}
