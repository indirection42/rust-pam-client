//! Functions interfacing with the conversation callback from C code

/***********************************************************************
 * (c) 2021 Christoph Grenz <christophg+gitorious @ grenz-bonn.de>     *
 *                                                                     *
 * This Source Code Form is subject to the terms of the Mozilla Public *
 * License, v. 2.0. If a copy of the MPL was not distributed with this *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.            *
 ***********************************************************************/

use super::ConversationHandler;
use super::resp_buf::{ResponseBuffer};
use crate::error::ReturnCode;

use std::mem::size_of;
use std::slice;
use std::ffi::{CStr, CString};
use libc::{c_int, c_void};
use pam_sys::types::{PamResponse, PamConversation, PamMessage, PamMessageStyle as MessageStyle};

/// Wraps `callback` along with [`pam_converse<T>`] for handing to libpam.
pub(crate) fn to_pam_conv<T: ConversationHandler>(callback: &mut Box<T>) -> PamConversation {
	PamConversation {
		conv: Some(pam_converse::<T>),
		data_ptr: (&mut **callback) as *mut T as *mut libc::c_void,
	}
}

/// Maps `prompt_*` success results to `Option<CString>`.
///
/// Might get more complex in case we change the function signatures in the
/// future.
fn map_conv_string(input: CString) -> Option<CString> {
	Some(input)
}

/// Converts the message pointer into a slice for easy iteration.
///
/// Version for Linux, NetBSD and similar platforms that interpret
/// `**PamMessage` as "array of pointers to PamMessage structs".
#[cfg(not(target_os="solaris"))]
#[inline]
fn msg_to_slice(msg: &*mut *mut PamMessage, num_msg: c_int) -> &[&PamMessage] {
	// This is sound, as [&PamMessage] has the same layout as "array of ptrs
	// to PamMessage structs" and msgs lives at least until we return.
	unsafe { slice::from_raw_parts((*msg) as *const &PamMessage, num_msg as usize) }
}

/// Converts the message pointer into a slice for easy iteration.
///
/// Version for Solaris and similar platforms that interpret `**PamMessage`
/// as "pointer to array of PamMessage structs".
#[cfg(target_os="solaris")]
#[inline]
fn msg_to_slice(msg: &*mut *mut PamMessage, num_msg: c_int) -> &'static [PamMessage] {
	// This is sound, as *[PamMessage] has the same layout as "ptr to array
	// of PamMessage structs" and msgs lives at least until we return.
	unsafe { slice::from_raw_parts((**msg) as *const PamMessage, num_msg as usize) }
}

/// Conversation function C library callback.
///
/// Will be called by C code when a conversation is requested. Does sanity
/// checks, prepares a response buffer and calls the conversation function
/// identified by `T` and `appdata_ptr` for each message.
pub(crate) extern "C" fn pam_converse<T: ConversationHandler>(
	num_msg: c_int,
	msg: *mut *mut PamMessage,
	out_resp: *mut *mut PamResponse,
	appdata_ptr: *mut c_void
) -> c_int {
	const MAX_MSG_NUM: isize = isize::MAX / size_of::<* const PamMessage>() as isize;

	// Check for null pointers
	if msg.is_null() || out_resp.is_null() || appdata_ptr.is_null() {
		return ReturnCode::BUF_ERR as i32;
	}

	// Extract conversation handler from `appdata_ptr`.
	// This is sound, as we did the reverse in `Context::new()`.
	let handler = unsafe { &mut *(appdata_ptr as *mut T) };

	// Prepare response buffer
	let mut responses = match ResponseBuffer::new(num_msg as isize) {
		Ok(buf) => buf,
		Err(e) => return e.code() as i32
	};

	// Check preconditions for slice::from_raw_parts.
	// (the checks in `ResponseBuffer::new` are even stricter but better be
	// safe than sorry).
	if !(0..=MAX_MSG_NUM).contains(&(num_msg as isize)) {
		return ReturnCode::BUF_ERR as i32;
	}

	// Cast `msg` with `num_msg` to a slice for easy iteration.
	let messages = msg_to_slice(&msg, num_msg);

	// Call conversation handler for each message
	for (i, message) in messages.iter().enumerate() {
		// This is sound as long as the PAM modules play by the rules
		// and the correct `msg_to_slice` implementation was selected
		// by the build process.
		let text = unsafe {
			// Extra safeguard against stray NULL pointers
			if message.msg.is_null() {
				CStr::from_bytes_with_nul_unchecked(b"\0")
			} else {
				CStr::from_ptr(message.msg)
			}
		};
		
		// Delegate to the correct handler method based on `msg_style`
		let result = match MessageStyle::from(message.msg_style) {
			MessageStyle::PROMPT_ECHO_ON => handler.prompt_echo_on(text).map(map_conv_string),
			MessageStyle::PROMPT_ECHO_OFF => handler.prompt_echo_off(text).map(map_conv_string),
			MessageStyle::TEXT_INFO => { handler.text_info(text); Ok(None) },
			MessageStyle::ERROR_MSG => { handler.error_msg(text); Ok(None) },
		};

		// Process response and bail out on errors
		match result {
			Ok(response) => responses.put(i, response),
			Err(ReturnCode::SUCCESS) => responses.put(i, None),
			Err(code) => return code as i32
		}
	}

	// Transfer responses to caller and return.
	// Sound as long as the PAM modules play by the rules..
	unsafe { *out_resp = responses.into() };
	ReturnCode::SUCCESS as i32
}

#[cfg(test)]
mod tests {
	use std::ptr;
	use libc::free;
	use super::*;
	use crate::conv_mock::{Conversation, LogEntry};

	fn make_handler() -> (Box<Conversation>, PamConversation) {
		let mut handler = Box::new(Conversation::with_credentials("test usër", "paßword"));
		let pam_conv = to_pam_conv(&mut handler);
		return (handler, pam_conv);
	}

	/// Check edge cases for invalid parameters to `pam_conv`
	#[test]
	fn test_edge_cases() {
		let (handler, pam_conv) = make_handler();
		let c_callback = pam_conv.conv.unwrap();
		let appdata = pam_conv.data_ptr;

		let text = CString::new("").unwrap();
		let mut msg = PamMessage {
			msg_style: MessageStyle::PROMPT_ECHO_ON as i32,
			msg: text.as_ptr()
		};
		let mut msg_ptr = &mut msg as *mut PamMessage;

		let mut responses: *mut PamResponse = ptr::null_mut();

		assert_eq!(
			c_callback(
				1,
				ptr::null_mut(),
				&mut responses as *mut *mut PamResponse,
				appdata,
			),
			ReturnCode::BUF_ERR as i32,
			"pam_conv with null `msg` arg returned `left` instead of BUF_ERR"
		);

		assert_eq!(
			c_callback(
				1,
				&mut msg_ptr as *mut *mut PamMessage,
				ptr::null_mut(),
				appdata,
			),
			ReturnCode::BUF_ERR as i32,
			"pam_conv with null `out_resp` arg returned `left` instead of BUF_ERR"
		);

		assert_eq!(
			c_callback(
				1,
				&mut msg_ptr as *mut *mut PamMessage,
				&mut responses as *mut *mut PamResponse,
				ptr::null_mut(),
			),
			ReturnCode::BUF_ERR as i32,
			"pam_conv with null `appdata_ptr` arg returned `left` instead of BUF_ERR"
		);

		assert_eq!(
			c_callback(
				-1,
				&mut msg_ptr as *mut *mut PamMessage,
				&mut responses as *mut *mut PamResponse,
				appdata,
			),
			ReturnCode::BUF_ERR as i32,
			"pam_conv with negative `msg_num` arg returned `left` instead of BUF_ERR"
		);

		// There should be exactly zero message in the log
		assert_eq!(handler.log.len(), 0, "log contained `left` messages instead of `right`");
	}

	/// Check if `pam_conv` rejects `0` as `num_msg` argument
	///
	/// This is not required by the standard, but our own policy, to keep this
	/// case defined.
	#[test]
	fn test_zero_num() {
		let (handler, pam_conv) = make_handler();
		let c_callback = pam_conv.conv.unwrap();
		let appdata = pam_conv.data_ptr;

		let mut msg = PamMessage {
			msg_style: MessageStyle::PROMPT_ECHO_ON as i32,
			msg: ptr::null_mut()
		};
		let mut msg_ptr = &mut msg as *mut PamMessage;

		let mut responses: *mut PamResponse = ptr::null_mut();

		// zero `msg_num` should fail
		assert_eq!(
			c_callback(
				0,
				&mut msg_ptr as *mut *mut PamMessage,
				&mut responses as *mut *mut PamResponse,
				appdata,
			),
			ReturnCode::BUF_ERR as i32,
			"pam_conv with zero `msg_num` arg returned `left` instead of BUF_ERR"
		);

		// There should be exactly zero message in the log
		assert_eq!(handler.log.len(), 0, "log contained `left` messages instead of `right`");
	}

	/// Check if `pam_conv` correctly answers a prompt
	fn test_prompt(style: MessageStyle, prompt: &str, expected: &str) {
		let (handler, pam_conv) = make_handler();
		let c_callback = pam_conv.conv.unwrap();
		let appdata = pam_conv.data_ptr;

		let text = CString::new(prompt).unwrap();
		let mut msg = PamMessage {
			msg_style: style as i32,
			msg: text.as_ptr()
		};
		let mut msg_ptr = &mut msg as *mut PamMessage;

		let mut responses: *mut PamResponse = ptr::null_mut();

		let code = c_callback(
			1,
			&mut msg_ptr as *mut *mut PamMessage,
			&mut responses as *mut *mut PamResponse,
			appdata,
		);
		assert_eq!(
			code,
			ReturnCode::SUCCESS as i32,
			"pam_conv failed with error code `left`"
		);

		assert!(
			!responses.is_null(),
			"response is still null after conversation"
		);

		assert_eq!(
			unsafe { (*responses).resp_retcode },
			0,
			"retcode in response is `left` instead of 0"
		);

		let response = unsafe { CStr::from_ptr((*responses).resp) };

		assert_eq!(
			response,
			CString::new(expected).unwrap().as_c_str(),
			"response contained `left` instead of expected `right`"
		);

		unsafe {
			free((*responses).resp as *mut c_void);
			free(responses as *mut c_void);
		}

		// There should be exactly zero message in the log
		assert_eq!(handler.log.len(), 0, "log contained `left` messages instead of `right`");
	}
	
	/// Check if `pam_conv` correctly answers an echoing prompt
	#[test]
	fn test_prompt_echo_on() {
		test_prompt(MessageStyle::PROMPT_ECHO_ON, "username? ", "test usër")
	}

	/// Check if `pam_conv` correctly answers a secret prompt
	#[test]
	fn test_prompt_echo_off() {
		test_prompt(MessageStyle::PROMPT_ECHO_OFF, "password? ", "paßword")
	}

	/// Check if `pam_conv` correctly handles a info/error message
	fn test_output_msg(style: MessageStyle, text: &str) -> LogEntry {
		let (handler, pam_conv) = make_handler();
		let c_callback = pam_conv.conv.unwrap();
		let appdata = pam_conv.data_ptr;

		let c_text = CString::new(text).unwrap();
		let mut msg = PamMessage {
			msg_style: style as i32,
			msg: c_text.as_ptr()
		};
		let mut msg_ptr = &mut msg as *mut PamMessage;

		let mut responses: *mut PamResponse = ptr::null_mut();

		let code = c_callback(
			1,
			&mut msg_ptr as *mut *mut PamMessage,
			&mut responses as *mut *mut PamResponse,
			appdata,
		);
		assert_eq!(
			code,
			ReturnCode::SUCCESS as i32,
			"pam_conv failed with error code `left`"
		);

		assert!(
			!responses.is_null(),
			"response is still null after conversation"
		);

		assert_eq!(
			unsafe { (*responses).resp_retcode },
			0,
			"retcode in response is `left` instead of 0"
		);

		assert_eq!(
			unsafe { (*responses).resp },
			ptr::null_mut(),
			"response text is non-null after output-only conversation"
		);

		unsafe {
			free(responses as *mut c_void);
		}

		// There should be exactly one message in the log
		assert_eq!(handler.log.len(), 1, "log contained `left` messages instead of `right`");

		return handler.log[0].clone()
	}

	/// Check if `pam_conv` correctly transmits an error message
	#[test]
	fn test_error_msg() {
		const MSG: &str = "test error öäüß";
		let logentry = test_output_msg(MessageStyle::ERROR_MSG, MSG);
		if let LogEntry::Error(msg) = logentry {
			assert_eq!(msg.to_string_lossy(), MSG, "log contained unexpected message `left`");
		} else {
			assert!(false, "log contained unexpected message type");
		}
	}

	/// Check if `pam_conv` correctly transmits an info message
	#[test]
	fn test_info_msg() {
		const MSG: &str = "test info äöüß";
		let logentry = test_output_msg(MessageStyle::TEXT_INFO, MSG);
		if let LogEntry::Info(msg) = logentry {
			assert_eq!(msg.to_string_lossy(), MSG, "log contained unexpected message `left`");
		} else {
			assert!(false, "log contained unexpected message type");
		}
	}
}
