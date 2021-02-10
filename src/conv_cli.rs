/*!
 * Interactive command line conversation handler
 *
 * *This module is unavailable if pam-client is built without the `"cli"` feature.*
 */


use std::io::{self, Write, BufRead};
use std::ffi::{CStr, CString};
use crate::error::ReturnCode;
use super::ConversationHandler;

/// Newline trimming helper function
fn trim_newline(s: &mut String) {
	if s.ends_with('\n') {
		s.pop();
		if s.ends_with('\r') {
			s.pop();
		}
	}
}

/// Command-line implementation of `ConversationHandler`
///
/// *This struct is unavailable if pam-client is built without the `"cli"` feature.*
///
/// Prompts, info and error messages will be written to STDERR, non-secret
/// input in read from STDIN and [rpassword][`rpassword::read_password_from_tty`]
/// is used to prompt the user for passwords.
///
/// # Limitations
///
/// Please note that UTF-8 encoding is assumed for terminal I/O, so this
/// handler may fail to authenticate on legacy non-UTF-8 systems when the user
/// input contains non-ASCII characters.
#[derive(Debug, Clone)]
pub struct Conversation {
	info_prefix: String,
	error_prefix: String,
}

impl Conversation {
	/// Creates a new CLI conversation handler.
	#[must_use]
	pub fn new() -> Self {
		Self {
			info_prefix: "[PAM INFO] ".to_string(),
			error_prefix: "[PAM ERROR] ".to_string(),
		}
	}

	/// The prefix text written before info text
	#[inline]
	#[must_use]
	pub fn info_prefix(&self) -> &str {
		&self.info_prefix
	}

	/// Updates the prefix put before info text
	pub fn set_info_prefix(&mut self, prefix: impl Into<String>) {
		self.info_prefix = prefix.into();
	}

	/// The prefix text written before error messages
	#[inline]
	#[must_use]
	pub fn error_prefix(&self) -> &str {
		&self.error_prefix
	}

	/// Updates the prefix put before error messages
	pub fn set_error_prefix(&mut self, prefix: impl Into<String>) {
		self.error_prefix = prefix.into();
	}
}

impl Default for Conversation {
	fn default() -> Self {
		Self::new()
	}
}

impl ConversationHandler for Conversation {
	fn prompt_echo_on(&mut self, msg: &CStr) -> Result<CString, ReturnCode> {
		let mut line = String::new();
		if io::stderr().lock().write_all(msg.to_bytes()).is_err() {
			return Err(ReturnCode::CONV_ERR);
		}
		match io::stdin().lock().read_line(&mut line) {
			Err(_) | Ok(0) => Err(ReturnCode::CONV_ERR),
			Ok(_) => {
				trim_newline(&mut line);
				CString::new(line).map_err(|_| ReturnCode::CONV_ERR)
			}
		}
	}

	fn prompt_echo_off(&mut self, msg: &CStr) -> Result<CString, ReturnCode> {
		let prompt = msg.to_string_lossy();
		match rpassword::read_password_from_tty(Some(&prompt)) {
			Err(_) => Err(ReturnCode::CONV_ERR),
			Ok(password) => CString::new(password).map_err(|_| ReturnCode::CONV_ERR)
		}
	}

	fn text_info(&mut self, msg: &CStr) {
		eprintln!("{}{}", &self.info_prefix, msg.to_string_lossy());
	}

	fn error_msg(&mut self, msg: &CStr) {
		eprintln!("{}{}", &self.error_prefix, msg.to_string_lossy());
	}
}
