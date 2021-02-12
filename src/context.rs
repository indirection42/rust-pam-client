//! PAM context and related helpers

/***********************************************************************
 * (c) 2021 Christoph Grenz <christophg+gitorious @ grenz-bonn.de>     *
 *                                                                     *
 * This Source Code Form is subject to the terms of the Mozilla Public *
 * License, v. 2.0. If a copy of the MPL was not distributed with this *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.            *
 ***********************************************************************/

use crate::ConversationHandler;
use crate::ffi::to_pam_conv;
use crate::error::{ReturnCode, Error};
use crate::session::{Session, SessionToken};
use crate::env_list::EnvList;
extern crate libc;
extern crate pam_sys;

use crate::{Result, ExtResult, Flag};

use std::ffi::{CStr, CString};
use std::{ptr, slice};
use std::convert::TryFrom;
use std::cell::Cell;
use std::mem::take;
use libc::{c_char, c_int, c_void};
use pam_sys::types::{PamItemType, PamHandle, PamConversation};
use pam_sys::wrapped::{start, end, get_item, set_item, setcred, authenticate, acct_mgmt, chauthtok, open_session, close_session, getenvlist, getenv, putenv};

/// Internal: Builds getters/setters for string-typed PAM items.
macro_rules! impl_pam_str_item {
	($name:ident, $set_name:ident, $item_type:expr$(, $doc:literal$(, $extdoc:literal)?)?$(,)?) => {
		$(#[doc = "Returns "]#[doc = $doc]$(#[doc = "\n\n"]#[doc = $extdoc])?)?
		pub fn $name(&self) -> Result<Option<String>> {
			let ptr = self.get_item($item_type)?;
			if ptr.is_null() {
				return Ok(None);
			}
			let string = unsafe { CStr::from_ptr(ptr as *const libc::c_char) }.to_string_lossy().into_owned();
			return Ok(Some(string));
		}
		
		$(#[doc = "Sets "]#[doc = $doc])?
		pub fn $set_name(&mut self, value: Option<&str>) -> Result<()> {
			match value {
				None => unsafe { self.set_item($item_type, ptr::null()) },
				Some(string) => {
					let cstring = CString::new(string).map_err(|_| Error::new(self.handle(), ReturnCode::BUF_ERR))?;
					unsafe { self.set_item($item_type, cstring.as_ptr() as *const c_void) }
				}
			}
		}
	}
}

/// Special struct for the `PAM_XAUTHDATA` pam item
///
/// Differs from [`pam_sys::types::PamXAuthData`] by using const pointers
/// as `pam_set_item` makes a copy of the data and never mutates through
/// the pointers and `pam_get_item` by API contract states that returned
/// data should not be modified.
#[cfg(any(target_os="linux",doc))]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct XAuthData {
	/// Length of `name` in bytes excluding the trailing NUL
	pub namelen: c_int,
	/// Name of the authentication method as a null terminated string
	pub name: *const c_char,
	/// Length of `data` in bytes
	pub datalen: c_int,
	/// Authentication method-specific data
	pub data: *const c_char,
}

/// Main struct for PAM interaction
///
/// Manages a PAM context holding the transaction state.
///
/// See the [crate documentation][`crate`] for examples.
pub struct Context<ConvT> where ConvT: ConversationHandler {
	handle: Cell<*mut PamHandle>,
	// Needs to be boxed, as we give a long-living pointer to it to C code.
	conversation: Box<ConvT>,
	last_status: Cell<ReturnCode>
}

impl<ConvT> Context<ConvT> where ConvT: ConversationHandler {

	/// Creates a PAM context and starts a PAM transaction.
	///
	/// # Parameters
	/// - `service` – Name of the service. The policy for the service will be
	///   read from the file /etc/pam.d/*service_name*, falling back to
	///   /etc/pam.conf.
	/// - `username` – Name of the target user. If `None`, the user will be
	///   asked through the conversation handler if neccessary.
	/// - `conversation` – A conversation handler through which the user can be
	///   asked for his username, password, etc. Use
	///   [`conv_cli::Conversation`][`crate::conv_cli::Conversation`] for a command line
	///   default implementation, [`conv_mock::Conversation`][`crate::conv_mock::Conversation`]
	///   for fixed credentials or implement the [`ConversationHandler`] trait
	///   for custom behaviour.
	///
	/// # Errors
	/// Expected error codes include:
	/// - `ReturnCode::ABORT` – General failure
	/// - `ReturnCode::BUF_ERR` – Memory allocation failure
	/// - `ReturnCode::SYSTEM_ERR` – Other system error
	#[rustversion::attr(since(1.48), doc(alias = "pam_start"))]
	pub fn new(service: &str, username: Option<&str>, conversation: ConvT) -> Result<Self> {
		// Wrap `conversation` in a box and delegate to `from_boxed_conv`
		Self::from_boxed_conv(service, username, Box::new(conversation))
	}

	/// Creates a PAM context and starts a PAM transaction taking a boxed
	/// conversation handler.
	///
	/// See [`new()`][`Self::new()`] for details.
	pub fn from_boxed_conv(service: &str, username: Option<&str>, mut boxed_conv: Box<ConvT>) -> Result<Self> {
		let mut handle: *mut PamHandle = ptr::null_mut();

		// Create callback struct for C code
		let pam_conv = to_pam_conv(&mut boxed_conv);

		// Start the PAM context
		match start(service, username, &pam_conv, &mut handle) {
			ReturnCode::SUCCESS => {
				// Should not happen, but for safetys sake check for a null
				// pointer on success.
				if handle.is_null() {
					Err(Error::try_from(ReturnCode::ABORT).unwrap())
				} else {
					boxed_conv.init(username);
					Ok(Self {
						handle: Cell::new(handle),
						conversation: boxed_conv,
						last_status: Cell::new(ReturnCode::SUCCESS),
					})
				}
			},
			code => Err(Error::try_from(code).unwrap())
		}
	}

	/// Internal: Gets the PAM handle.
	///
	/// This returns a mutable reference (as needed for all PAM lib calls)
	/// even when you have no mutable reference to `self`. Make sure to
	/// keep the reference for as brief as possible.
	#[inline]
	#[allow(clippy::mut_from_ref)]
	pub(crate) fn handle(&self) -> &mut PamHandle {
		let ptr = self.handle.as_ptr();
		unsafe { &mut **ptr }
	}

	/// Internal: Wraps a `ReturnCode` into a `Result` and sets `last_status`.
	#[inline]
	pub(crate) fn wrap_pam_return(&self, status: ReturnCode) -> Result<()> {
		self.last_status.set(status);
		match status {
			ReturnCode::SUCCESS => Ok(()),
			code => Err(Error::new(self.handle(), code))
		}
	}

	/// Returns a reference to the conversation handler.
	pub fn conversation(&self) -> &ConvT {
		&*(self.conversation)
	}

	/// Returns a mutable reference to the conversation handler.
	pub fn conversation_mut(&mut self) -> &mut ConvT {
		&mut *(self.conversation)
	}

	/// Returns raw PAM information.
	///
	/// If possible, use the convenience wrappers [`service()`][`Self::service()`],
	/// [`user()`][`Self::user()`], … instead.
	///
	/// # Errors
	/// Expected error codes include:
	/// - `BAD_ITEM` – Unsupported, undefined or inaccessible item
	/// - `BUF_ERR` – Memory buffer error
	/// - `PERM_DENIED` – The value was NULL
	#[rustversion::attr(since(1.48), doc(alias = "pam_get_item"))]
	pub fn get_item(&self, item_type: PamItemType) -> Result<*const c_void> {
		let mut result: *const c_void = ptr::null();
		self.wrap_pam_return(get_item(self.handle(), item_type, &mut result))?;
		Ok(result)
	}

	/// Updates raw PAM information.
	///
	/// If possible, use the convenience wrappers
	/// [`set_service()`][`Self::set_service()`],
	/// [`set_user()`][`Self::set_user()`], … instead.
	///
	/// # Errors
	/// Expected error codes include:
	/// - `BAD_ITEM` – Unsupported, undefined or inaccessible item
	/// - `BUF_ERR` – Memory buffer error
	///
	/// # Safety
	/// This method is unsafe. You must guarantee that the data pointed to by
	/// `value` matches the type the PAM library expects. E.g. a null terminated
	/// `*const c_char` for [`PamItemType::SERVICE`] or `*const PamXAuthData` for
	/// [`PamItemType::XAUTHDATA`].
	#[rustversion::attr(since(1.48), doc(alias = "pam_set_item"))]
	pub unsafe fn set_item(&mut self, item_type: PamItemType, value: *const c_void) -> Result<()> {
		self.wrap_pam_return(set_item(self.handle(), item_type, &*value))
	}

	impl_pam_str_item!(service, set_service, PamItemType::SERVICE, "the service name");
	impl_pam_str_item!(user, set_user, PamItemType::USER, "the username of the entity under whose identity service will be given",
		"This value can be mapped by any module in the PAM stack, so don't assume it stays unchanged after calling other methods on `Self`.");
	impl_pam_str_item!(user_prompt, set_user_prompt, PamItemType::USER_PROMPT, "the string used when prompting for a user's name");
	impl_pam_str_item!(tty, set_tty, PamItemType::TTY, "the terminal name");
	impl_pam_str_item!(ruser, set_ruser, PamItemType::RUSER, "the requesting user name");
	impl_pam_str_item!(rhost, set_rhost, PamItemType::RHOST, "the requesting hostname");
	#[cfg(any(target_os="linux",doc))]
	impl_pam_str_item!(authtok_type, set_authtok_type, PamItemType::AUTHTOK_TYPE, "the default password type in the prompt (Linux specific)", "E.g. \"UNIX\" for \"Enter UNIX password:\"");
	#[cfg(any(target_os="linux",doc))]
	impl_pam_str_item!(xdisplay, set_xdisplay, PamItemType::XDISPLAY, "the name of the X display (Linux specific)");

	/// Returns X authentication data as (name, value) pair (Linux specific).
	#[cfg(any(target_os="linux",doc))]
	pub fn xauthdata(&self) -> Result<Option<(&CStr, &[u8])>> {
		let ptr = self.get_item(PamItemType::XAUTHDATA)? as *const XAuthData;
		if ptr.is_null() {
			return Ok(None);
		}
		let data = unsafe { &*ptr };

		// Safety checks: validate the length are non-negative and that
		// the pointers are non-null
		if data.namelen < 0 || data.datalen < 0 || data.name.is_null() || data.data.is_null() {
			return Err(Error::new(self.handle(), ReturnCode::BUF_ERR))
		}

		#[allow(clippy::cast_sign_loss)]
		Ok(Some((
			CStr::from_bytes_with_nul(
				unsafe { slice::from_raw_parts(data.name as *const u8, data.namelen as usize + 1) }
			).map_err(|_| Error::new(self.handle(), ReturnCode::BUF_ERR))?,
			unsafe { slice::from_raw_parts(data.data as *const u8, data.datalen as usize) }
		)))
	}

	/// Sets X authentication data (Linux specific).
	///
	/// # Errors
	/// Expected error codes include:
	/// - `BAD_ITEM` – Unsupported item
	/// - `BUF_ERR` – Memory buffer error
	#[cfg(any(target_os="linux",doc))]
	pub fn set_xauthdata(&mut self, value: Option<(&CStr, &[u8])>) -> Result<()> {
		match value {
			None => unsafe { self.set_item(PamItemType::XAUTHDATA, ptr::null()) },
			Some((name, data)) => {
				let name_bytes = name.to_bytes_with_nul();

				if name_bytes.len() > i32::MAX as usize || data.len() > i32::MAX as usize {
					return Err(Error::new(self.handle(), ReturnCode::BUF_ERR))
				}

				#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
				let xauthdata = XAuthData {
					namelen: name_bytes.len() as i32 - 1,
					name: name_bytes.as_ptr() as *const libc::c_char,
					datalen: data.len() as i32,
					data: data.as_ptr() as *const libc::c_char
				};
				unsafe { self.set_item(PamItemType::XAUTHDATA, &xauthdata as *const XAuthData as *const c_void) }
			}
		}
	}

	/// Returns the value of a PAM environment variable.
	///
	/// Searches the environment list in this PAM context for an
	/// item with key `name` and returns the value, if it exists.
	#[rustversion::attr(since(1.48), doc(alias = "pam_getenv"))]
	pub fn getenv<'a>(&'a self, name: &str) -> Option<&'a str> {
		getenv(self.handle(), name)
	}

	/// Sets or unsets a PAM environment variable.
	///
	/// Modifies the environment list in this PAM context. The `name_value`
	/// argument can take one of the following forms:
	/// - *NAME*=*value* – Set a variable to a given value. If it was already
	///   set it is overwritten.
	/// - *NAME*= – Set a variable to the empty value. If it was already set
	///   it is overwritten.
	/// - *NAME* – Delete a variable, if it exists.
	#[rustversion::attr(since(1.48), doc(alias = "pam_putenv"))]
	pub fn putenv(&mut self, name_value: &str) -> Result<()> {
		self.wrap_pam_return(putenv(self.handle(), name_value))
	}

	/// Returns a copy of the PAM environment in this context.
	///
	/// The contained variables represent the contents of the regular
	/// environment variables of the authenticated user when service is
	/// granted.
	///
	/// The returned [`EnvList`] type is designed to ease handing the
	/// environment to [`std::process::Command::envs()`] and
	/// `nix::unistd::execve`.
	#[rustversion::attr(since(1.48), doc(alias = "pam_getenvlist"))]
	pub fn envlist(&self) -> EnvList {
		unsafe { EnvList::new(getenvlist(self.handle()) as *mut *mut c_char) }
	}

	/// Authenticates a user.
	///
	/// The conversation handler may be called to ask the user for their name
	/// (especially if no default username was provided), their password and
	/// possibly other tokens if e.g. two-factor authentication is required.
	/// Conversely the conversation handler may not be called if authentication
	/// is handled by other means, e.g. a fingerprint scanner.
	///
	/// Relevant `flags` are [`Flag::NONE`], [`Flag::SILENT`] and
	/// [`Flag::DISALLOW_NULL_AUTHTOK`] (don't authenticate empty
	/// passwords).
	///
	/// # Errors
	/// Expected error codes include:
	/// - `ABORT` – Serious failure; the application should exit.
	/// - `AUTH_ERR` – The user was not authenticated.
	/// - `CRED_INSUFFICIENT` – The application does not have sufficient
	///   credentials to authenticate the user.
	/// - `AUTHINFO_UNAVAIL` – Could not retrieve authentication information
	///   due to e.g. network failure.
	/// - `MAXTRIES` – At least one module reached its retry limit. Do not
	/// - try again.
	/// - `USER_UNKNOWN` – User not known.
	/// - `INCOMPLETE` – The conversation handler returned `CONV_AGAIN`. Call
	///   again after the asynchronous conversation finished.
	#[rustversion::attr(since(1.48), doc(alias = "pam_authenticate"))]
	pub fn authenticate(&mut self, flags: Flag) -> Result<()> {
		self.wrap_pam_return(authenticate(self.handle(), flags))
	}

	/// Validates user account authorization.
	///
	/// Determines if the account is valid, not expired, and verifies other
	/// access restrictions. Usually used directly after authentication.
	/// The conversation handler may be called by some PAM module.
	///
	/// Relevant `flags` are [`Flag::NONE`], [`Flag::SILENT`] and
	/// [`Flag::DISALLOW_NULL_AUTHTOK`] (demand password change on empty
	/// passwords).
	///
	/// # Errors
	/// Expected error codes include:
	/// - `ACCT_EXPIRED` – Account has expired.
	/// - `AUTH_ERR` – Authentication failure.
	/// - `NEW_AUTHTOK_REQD` – Password has expired. Use [`chauthtok()`] to let
	///   the user change their password or abort.
	/// - `PERM_DENIED` – Permission denied
	/// - `USER_UNKNOWN` – User not known
	/// - `INCOMPLETE` – The conversation handler returned `CONV_AGAIN`. Call
	///   again after the asynchronous conversation finished.
	#[rustversion::attr(since(1.48), doc(alias = "pam_acct_mgmt"))]
	pub fn acct_mgmt(&mut self, flags: Flag) -> Result<()> {
		self.wrap_pam_return(acct_mgmt(self.handle(), flags))
	}

	/// Fully reinitializes the user's credentials (if established).
	///
	/// Reinitializes credentials like Kerberos tokens for when a session
	/// is already managed by another process. This is e.g. used in
	/// lockscreen applications to refresh the credentials of the desktop
	/// session.
	///
	/// Because of limitations in [`pam_sys`] the flags are currently ignored.
	/// Use [`Flag::NONE`] or [`Flag::SILENT`].
	///
	/// # Errors
	/// Expected error codes include:
	/// - `BUF_ERR` – Memory allocation error
	/// - `CRED_ERR` – Setting credentials failed
	/// - `CRED_UNAVAIL` – Failed to retrieve credentials
	/// - `SYSTEM_ERR` – Other system error
	/// - `USER_UNKNOWN` – User not known
	pub fn reinitialize_credentials(&mut self, _flags: Flag) -> Result<()> {
		self.wrap_pam_return(setcred(self.handle(), Flag::REINITIALIZE_CRED/*|flags*/))
	}

	/// Changes a users password.
	///
	/// The conversation handler will be used to request the new password
	/// and might query for the old one.
	///
	/// Relevant `flags` are [`Flag::NONE`], [`Flag::SILENT`] and
	/// [`Flag::CHANGE_EXPIRED_AUTHTOK`] (only initiate change for
	/// expired passwords).
	///
	/// # Errors
	/// Expected error codes include:
	/// - `AUTHTOK_ERR` – Unable to obtain the new password
	/// - `AUTHTOK_RECOVERY_ERR` – Unable to obtain the old password
	/// - `AUTHTOK_LOCK_BUSY` – Authentication token is currently locked
	/// - `AUTHTOK_DISABLE_AGING` – Password aging is disabled (password may
	///   be unchangeable in at least one module)
	/// - `PERM_DENIED` – Permission denied
	/// - `TRY_AGAIN` – Not all modules were able to prepare an authentication
	///   token update. Nothing was changed.
	/// - `USER_UNKNOWN` – User not known
	/// - `INCOMPLETE` – The conversation handler returned `CONV_AGAIN`. Call
	///   again after the asynchronous conversation finished.
	#[rustversion::attr(since(1.48), doc(alias = "pam_chauthtok"))]
	pub fn chauthtok(&mut self, flags: Flag) -> Result<()> {
		self.wrap_pam_return(chauthtok(self.handle(), flags))
	}

	/// Sets up a user session.
	///
	/// Establishes user credentials and performs various tasks to prepare
	/// a login session, may create the home directory on first login, mount
	/// user-specific directories, log access times, etc. The application
	/// must usually have sufficient privileges to perform this task (e.g.
	/// have EUID 0). The returned [`Session`] object closes the session and
	/// deletes the established credentials on drop.
	///
	/// The user should already be [authenticated] and [authorized] at this
	/// point, but this isn't enforced or strictly neccessary if the user
	/// was authenticated by other means. In that case the conversation
	/// handler might be called by e.g. crypt-mount modules to get a password.
	///
	/// Relevant `flags` are [`Flag::NONE`] and [`Flag::SILENT`].
	///
	/// # Errors
	/// Expected error codes include:
	/// - `ABORT` – Serious failure; the application should exit
	/// - `BUF_ERR` – Memory allocation error
	/// - `SESSION_ERR` – Some session initialization failed
	/// - `CRED_ERR` – Setting credentials failed
	/// - `CRED_UNAVAIL` – Failed to retrieve credentials
	/// - `SYSTEM_ERR` – Other system error
	/// - `USER_UNKNOWN` – User not known
	/// - `INCOMPLETE` – The conversation handler returned `CONV_AGAIN`. Call
	///   again after the asynchronous conversation finished.
	///
	/// [authenticated]: authenticate()
	/// [authorized]: acct_mgmt()
	#[rustversion::attr(since(1.48), doc(alias = "pam_open_session"))]
	pub fn open_session(&mut self, flags: Flag) -> Result<Session<ConvT>> {
		self.wrap_pam_return(setcred(self.handle(), Flag::ESTABLISH_CRED/*|flags*/))?;

		if let Err(e) = self.wrap_pam_return(open_session(self.handle(), flags)) {
			let _ = self.wrap_pam_return(setcred(self.handle(), Flag::DELETE_CRED/*|flags*/));
			return Err(e);
		}

		// Reinitialize credentials after session opening. With this we try
		// to circumvent different assumptions of PAM modules about when
		// `setcred` is called, as the documentations of different PAM
		// implementations differ. (OpenSSH does something similar too).
		if let Err(e) = self.wrap_pam_return(setcred(self.handle(), Flag::REINITIALIZE_CRED/*|flags*/)) {
			let _ = self.wrap_pam_return(close_session(self.handle(), flags));
			let _ = self.wrap_pam_return(setcred(self.handle(), Flag::DELETE_CRED/*|flags*/));
			return Err(e);
		}

		Ok(Session::new(self, true))
	}

	/// Maintains user credentials but don't set up a full user session.
	///
	/// Establishes user credentials and returns a [`Session`] object that
	/// deletes the credentials on drop. It doesn't open a PAM session.
	///
	/// The user should already be [authenticated] and [authorized] at this
	/// point, but this isn't enforced or strictly neccessary.
	///
	/// Depending on the platform this use case may not be fully supported.
	///
	/// Because of limitations in [`pam_sys`] the flags are currently ignored.
	/// Use [`Flag::NONE`] or [`Flag::SILENT`].
	///
	/// # Errors
	/// Expected error codes include:
	/// - `BUF_ERR` – Memory allocation error
	/// - `CRED_ERR` – Setting credentials failed
	/// - `CRED_UNAVAIL` – Failed to retrieve credentials
	/// - `SYSTEM_ERR` – Other system error
	/// - `USER_UNKNOWN` – User not known
	///
	/// [authenticated]: Self::authenticate()
	/// [authorized]: Self::acct_mgmt()
	pub fn open_pseudo_session(&mut self, _flags: Flag) -> Result<Session<ConvT>> {
		self.wrap_pam_return(setcred(self.handle(), Flag::ESTABLISH_CRED/*|flags*/))?;

		Ok(Session::new(self, false))
	}

	/// Resume a session from a [`SessionToken`].
	pub fn unleak_session(&mut self, token: SessionToken) -> Session<ConvT> {
		Session::new(
			self,
			matches!(token, SessionToken::FullSession)
		)
	}
}

impl<ConvT> Context<ConvT> where ConvT: ConversationHandler + Default {
	/// Swap the conversation handler.
	///
	/// Consumes the context, returns the new context and the old conversation
	/// handler.
	///
	/// # Errors
	/// Expected error codes include:
	/// - `BAD_ITEM` – Swapping the conversation handler is unsupported
	/// - `BUF_ERR` – Memory buffer error
	///
	/// The error payload contains the old context and the new handler.
	pub fn replace_conversation<T: ConversationHandler>(self, new_handler: T) -> ExtResult<(Context<T>, ConvT), (Self, T)> {
		match self.replace_conversation_boxed(new_handler.into()) {
			Ok((context, boxed_old_conv)) => Ok((context, *boxed_old_conv)),
			Err(error) => Err(error.map(|(ctx, b_conv)| (ctx, *b_conv))),
		}
	}

	/// Swap the conversation handler (boxed variant).
	///
	/// See [`replace_conversation()`][`Self::replace_conversation()`].
	pub fn replace_conversation_boxed<T: ConversationHandler>(mut self, mut new_handler: Box<T>) -> ExtResult<(Context<T>, Box<ConvT>), (Self, Box<T>)> {
		// Get current username for handler initialization
		let username = match self.user() {
			Ok(u) => u,
			Err(e) => return Err(e.into_with_payload((self, new_handler)))
		};
		// Create callback struct for C code
		let pam_conv = to_pam_conv(&mut new_handler);
		if let Err(e) = unsafe { self.set_item(PamItemType::CONV, &pam_conv as *const PamConversation as *const c_void) } {
			Err(e.into_with_payload((self, new_handler)))
		} else {
			// Initialize handler
			new_handler.init(username);
			// Create new context and return it
			Ok((
				Context::<T> {
					handle: Cell::new(self.handle.replace(ptr::null_mut())),
					conversation: new_handler,
					last_status: Cell::new(self.last_status.replace(ReturnCode::SUCCESS))
				},
				take(&mut self.conversation)
			))
		}
	}
}

/// Destructor ending the PAM transaction and releasing the PAM context
impl<ConvT> Drop for Context<ConvT> where ConvT: ConversationHandler {
	#[rustversion::attr(since(1.48), doc(alias = "pam_end"))]
	fn drop(&mut self) {
		end(self.handle(), self.last_status.get());
	}
}

// `Send` should be possible, as long as `ConvT` is `Send` too, as all memory
// access is bound to an unique instance of `Context` (no copy/clone) and we
// keep interior mutability bound to having a reference to the instance.
unsafe impl<ConvT> Send for Context<ConvT> where ConvT: ConversationHandler + Send {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_basic() {
		let mut context = Context::new(
			"test",
			Some("user"),
			crate::conv_null::Conversation::new()
		).unwrap();
		// Check if user name and service name are correctly saved
		assert_eq!(context.service().unwrap().unwrap(), "test");
		assert_eq!(context.user().unwrap().unwrap(), "user");
		// Check setting/getting of string items.
		context.set_ruser(Some("nobody")).unwrap();
		assert_eq!(context.ruser().unwrap().unwrap(), "nobody");
		// Check getting an unaccessible item
		assert!(context.get_item(PamItemType::AUTHTOK).is_err());
		// Check environment setting/getting
		context.putenv("TEST=1").unwrap();
		assert_eq!(context.getenv("TEST").unwrap(), "1");
		let env = context.envlist();
		assert!(env.len() > 0);
		for (key, value) in env.iter_tuples() {
			if key.to_string_lossy() == "TEST" {
				assert_eq!(value.to_string_lossy(), "1");
			}
		}
		drop(context)
	}

	#[test]
	fn test_conv_replace() {
		let mut context = Context::new(
			"test",
			Some("user"),
			crate::conv_null::Conversation::new()
		).unwrap();
		// Set username
		context.set_user(Some("anybody")).unwrap();
		// Replace conversation handler
		let (context, old_conv) = context.replace_conversation(crate::conv_mock::Conversation::default()).unwrap();
		// Check if set username was propagated to the new handler
		assert_eq!(context.conversation().username, "anybody");
		let (_context, _) = context.replace_conversation(old_conv).unwrap();
	}
}
