//! Conversation trait definition module

/***********************************************************************
 * (c) 2021 Christoph Grenz <christophg+gitorious @ grenz-bonn.de>     *
 *                                                                     *
 * This Source Code Form is subject to the terms of the Mozilla Public *
 * License, v. 2.0. If a copy of the MPL was not distributed with this *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.            *
 ***********************************************************************/

use crate::error::ReturnCode;
use std::ffi::{CString, CStr};
use std::result::Result;

/// Trait for PAM conversation functions
///
/// Implement this for custom behaviour when a PAM module asks for usernames,
/// passwords, etc. or wants to show a message to the user
pub trait ConversationHandler {
	/// Called by [`Context`][`crate::Context`] directly after taking ownership
	/// of the handler.
	///
	/// May be called multiple times if
	/// [`Context::replace_conversation()`][`crate::Context::replace_conversation`]
	/// is used. In this case it is called each time a context takes ownership
	/// and passed the current target username of that context (if any) as the
	/// argument.
	///
	/// The default implementation does nothing.
	fn init(&mut self, _default_user: Option<impl AsRef<str>>) {}

	/// Obtains a string whilst echoing text (e.g. username)
	///
	/// # Errors
	/// You should return one of the following error codes on failure.
	/// - [`ReturnCode::CONV_ERR`]: Conversation failure.
    /// - [`ReturnCode::BUF_ERR`]: Memory allocation error.
	/// - [`ReturnCode::CONV_AGAIN`]: no result yet, the PAM library should
	///   pass [`ReturnCode::INCOMPLETE`] to the application and let it
	///   try again later.
	fn prompt_echo_on(&mut self, prompt: &CStr) -> Result<CString, ReturnCode>;

	/// Obtains a string without echoing any text (e.g. password)
	///
	/// # Errors
	/// You should return one of the following error codes on failure.
	/// - [`ReturnCode::CONV_ERR`]: Conversation failure.
    /// - [`ReturnCode::BUF_ERR`]: Memory allocation error.
	/// - [`ReturnCode::CONV_AGAIN`]: no result yet, the PAM library should
	///   pass [`ReturnCode::INCOMPLETE`] to the application and let it
	///   try again later.
	fn prompt_echo_off(&mut self, prompt: &CStr) -> Result<CString, ReturnCode>;

	/// Displays some text.
	fn text_info(&mut self, msg: &CStr);

	/// Displays an error message.
	fn error_msg(&mut self, msg: &CStr);
}
