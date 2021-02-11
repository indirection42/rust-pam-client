//! Null conversation handler

/***********************************************************************
 * Author: Christoph Grenz <christophg+gitorious @ grenz-bonn.de>      *
 *                                                                     *
 * Due to the lack of originality the Null conversation handler        *
 * implementation is given to the public domain. To the extent         *
 * possible under law, the author has waived all copyright and related *
 * or neighboring rights to this Source Code Form.                     *
 * https://creativecommons.org/publicdomain/zero/1.0/legalcode         *
 ***********************************************************************/

use std::ffi::{CStr, CString};
use crate::error::ReturnCode;
use super::ConversationHandler;

/// Null implementation of `ConversationHandler`
///
/// When a PAM module asks for any user interaction an error is returned.
/// Error and info messages are and ignored.
///
/// This handler may be used for testing and for environments where no user
/// interaction is possible, no credentials can be stored beforehand and
/// failing is the only answer if some PAM module needs input.
#[derive(Debug, Clone)]
pub struct Conversation {}

impl Conversation {
	/// Creates a new null conversation handler
	#[must_use]
	pub const fn new() -> Self {
		Self {}
	}
}

impl Default for Conversation {
	fn default() -> Self {
		Self::new()
	}
}

impl ConversationHandler for Conversation {
	fn prompt_echo_on(&mut self, _msg: &CStr) -> Result<CString, ReturnCode> {
		Err(ReturnCode::CONV_ERR)
	}

	fn prompt_echo_off(&mut self, _msg: &CStr) -> Result<CString, ReturnCode> {
		Err(ReturnCode::CONV_ERR)
	}

	fn text_info(&mut self, _msg: &CStr) {}

	fn error_msg(&mut self, _msg: &CStr) {}
}
