//! Null conversation handler

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
	pub fn new() -> Self {
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
