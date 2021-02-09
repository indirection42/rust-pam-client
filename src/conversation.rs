//! Conversation trait definition module
use crate::error::ReturnCode;
use std::ffi::{CString, CStr};
use std::result::Result;

/// Trait for PAM conversation functions
///
/// Implement this for custom behaviour when a PAM module asks for usernames,
/// passwords, etc. or wants to show a message to the user
pub trait ConversationHandler {
	/// Called by [`Context`][`crate::Context`] after taking ownership of the
	/// handler and before any other callback is called.
	fn init(&mut self, _default_user: Option<&str>) {}

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
