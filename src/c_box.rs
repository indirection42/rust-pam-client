//! Helper module for safe building of PAM responses

/***********************************************************************
 * (c) 2021 Christoph Grenz <christophg+gitorious @ grenz-bonn.de>     *
 *                                                                     *
 * This Source Code Form is subject to the terms of the Mozilla Public *
 * License, v. 2.0. If a copy of the MPL was not distributed with this *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.            *
 ***********************************************************************/

#![allow(dead_code)]

use crate::error::{Error, ReturnCode};
use crate::{Result, ExtResult};

use std::convert::TryFrom;
use std::ptr::NonNull;
use std::cmp::Ordering;
use std::ops::{Deref, DerefMut};
use std::hash::{Hasher, Hash};
use std::mem::MaybeUninit;
use std::{mem, slice, cmp, borrow};
use libc::{malloc, calloc, free, c_void};

/// A pointer type for C-compatible heap allocation.
///
/// Designed with a [`Box`]-like interface.
#[derive(Debug)]
#[repr(transparent)]
pub struct CBox<T: ?Sized> (NonNull<T>);

impl<T> CBox<T> {
	/// Allocates memory on the heap and then places `value` into it.
	///
	/// Panics if allocation fails.
	pub fn new(value: T) -> CBox<T> {
		Self::try_new(value).expect("memory allocation failed")
	}

	/// Tries to allocate memory on the heap and place `value` in it.
	///
	/// On failure the value is handed back in the error payload.
	pub fn try_new(value: T) -> ExtResult<Self, T> {
		let size = cmp::max(mem::size_of_val(&value), 1);
		if size > isize::MAX as usize {
			return Err(Self::buf_err().into_with_payload(value));
		}
		let ptr = unsafe {
			malloc(size)
		} as *mut T;
		match NonNull::new(ptr) {
			None => Err(Self::buf_err().into_with_payload(value)),
			Some(result) => {
				unsafe { *ptr = value };
				Ok(Self (result))
			}
		}
	}

	/// Allocates nulled memory on the heap.
	///
	/// # Panics
	/// Panics if allocation fails.
	pub fn new_zeroed() -> CBox<MaybeUninit<T>> {
		Self::try_new_zeroed().expect("memory allocation failed")
	}

	/// Tries to allocate nulled memory on the heap.
	///
	/// # Errors
	/// - `BUF_ERR` – Allocation failure or pointer preconditions unmet
	pub fn try_new_zeroed() -> Result<CBox<MaybeUninit<T>>> {
		let size = cmp::max(mem::size_of::<T>(), 1);
		if size > isize::MAX as usize {
			return Err(Self::buf_err());
		}
		let ptr = unsafe {
			calloc(1, size)
		} as *mut MaybeUninit<T>;
		match CBox::wrap(ptr) {
			None => Err(Self::buf_err()),
			Some(result) => Ok(result)
		}
	}

	/// Allocates nulled memory for `len` elements of `T` on the heap.
	///
	/// If you can guarantee that zeroed memory is a valid representation
	/// for T, use [`assume_all_init()`][`Self::assume_all_init()`] to
	/// strip the [`MaybeUninit`][`MaybeUninit`] wrapper.
	///
	/// # Panics
	/// Panics if allocation fails.
	pub fn new_zeroed_slice(len: usize) -> CBox<[MaybeUninit<T>]> {
		Self::try_new_zeroed_slice(len).expect("memory allocation failed")
	}

	/// Tries to allocate nulled memory for `len` elements of `T` on the heap.
	///
	/// If you can guarantee that zeroed memory is a valid representation
	/// for T, use [`assume_all_init()`][`Self::assume_all_init()`] to
	/// strip the [`MaybeUninit`][`MaybeUninit`] wrapper.
	///
	/// # Errors
	/// - `BUF_ERR` – Allocation failure or pointer preconditions unmet
	pub fn try_new_zeroed_slice(len: usize) -> Result<CBox<[MaybeUninit<T>]>> {
		let maxlen = isize::MAX as usize / mem::size_of::<T>();
		let size = cmp::max(mem::size_of::<T>(), 1);
		if size > isize::MAX as usize || len > maxlen {
			return Err(Self::buf_err());
		}
		let ptr = unsafe {
			calloc(len, size)
		} as *mut MaybeUninit<T>;

		match CBox::wrap_slice(ptr, len) {
			None => Err(Self::buf_err()),
			Some(result) => Ok(result)
		}
	}

	/// Internal: Wraps a pointer to a slice of `len` elements of `T`
	///
	/// Returns `None` if `raw` is null.
	fn wrap_slice(raw: *mut T, len: usize) -> Option<CBox<[T]>> {
		let slice = unsafe { slice::from_raw_parts_mut(raw, len) };
		CBox::wrap(slice)
	}

	/// Takes ownership of a pointer to a C array/slice.
	///
	/// The pointer must have been allocated with `malloc` or `calloc`.
	///
	/// # Panics
	/// Panics if `raw` is null.
	pub unsafe fn from_raw_slice(raw: *mut T, len: usize) -> CBox<[T]> {
		CBox::wrap_slice(raw, len).expect("cannot construct CBox from null pointer")
	}
}

impl<T> CBox<T> where T: ?Sized {
	/// Internal: Wraps a pointer to a `T`
	#[inline]
	fn wrap(raw: *mut T) -> Option<Self> {
		match NonNull::new(raw) {
			None => None,
			Some(result) => Some(Self (result))
		}
	}

	/// Internal: Builds an `Error` instance with `BUF_ERR` error code
	#[cold]
	fn buf_err() -> Error {
		Error::try_from(ReturnCode::BUF_ERR).unwrap()
	}

	/// Takes ownership of a pointer
	///
	/// The pointer must have been allocated with `malloc` or `calloc`.
	///
	/// # Panics
	/// Panics if `raw` is null.
	pub unsafe fn from_raw(raw: *mut T) -> CBox<T> {
		Self::wrap(raw).expect("cannot construct CBox from null pointer")
	}

	/// Consumes and leaks the `CBox`, returning a mutable reference, `&mut T`
	///
	/// The pointer must have been allocated with `malloc()` or `calloc()`.
	///
	/// Dropping the returned reference will cause a memory leak. If this is
	/// not acceptable, use [`CBox::from_raw()`] to reconstruct a `CBox`
	/// instance.
	pub fn leak<'a>(b: CBox<T>) -> &'a mut T {
		let ptr = CBox::into_raw(b);
		unsafe { &mut *ptr }
	}

	/// Consumes the `CBox`, returning the wrapped raw pointer.
	///
	/// The receiver of the pointer is responsible for the destruction and
	/// deallocation of T.
	///
	/// The memory may be released with [`libc::free()`], but then no
	/// destructors will be called. Use [`CBox::from_raw()`] instead to put
	/// the cleanup responsibility back to `CBox`.
	pub fn into_raw(b: CBox<T>) -> *mut T {
		let ptr: NonNull<T> = b.0;
		mem::forget(b);
		ptr.as_ptr()
	}
}

impl<T> CBox<[T]> {
	/// Consumes the `CBox`, returning a raw pointer without size information
	/// to the wrapped slice.
	///
	/// The receiver of the pointer is responsible for the destruction and
	/// deallocation of the slice memory.
	///
	/// The memory may be released with [`libc::free()`], but then no
	/// destructors will be called. Use [`CBox::from_raw_slice()`] instead
	/// to put the cleanup responsibility back to `CBox`.
	pub fn into_raw_unsized(b: CBox<[T]>) -> *mut T {
		let ptr: NonNull<[T]> = b.0;
		mem::forget(b);
		ptr.as_ptr() as *mut T
	}
}

impl<T> CBox<[MaybeUninit<T>]> {
	/// Converts a `CBox` containing `[MaybeUninit<T>]` to `CBox<[T]>` by
	/// assuming all the elements are in an initialized state.
	///
	/// # Safety
	/// It is up to the caller to guarantee that the `MaybeUninit<T>` elements
	/// really are in an initialized state. Calling this when the content is
	/// not yet fully initialized causes undefined behavior.
	pub unsafe fn assume_all_init(self) -> CBox<[T]> {
		CBox::<[T]> (
			NonNull::new_unchecked(CBox::into_raw(self) as *mut [T])
		)
	}
}

/// Destructor using [`libc::free()`] to release the allocated memory
impl<T: ?Sized> Drop for CBox<T> {
	fn drop(&mut self) {
		unsafe { free(self.0.as_ptr() as *mut c_void) };
	}
}

/// Easy boxing with `.from()`/`.into()`
impl<T> From<T> for CBox<T> {
	fn from(value: T) -> Self {
		Self::new(value)
	}
}

impl<T: ?Sized> Deref for CBox<T> {
	type Target = T;

	fn deref(&self) -> &T {
		unsafe { self.0.as_ref() }
	}
}

impl<T: ?Sized> DerefMut for CBox<T> {
	fn deref_mut(&mut self) -> &mut T {
		unsafe { self.0.as_mut() }
	}
}

impl<T: ?Sized + PartialEq> PartialEq for CBox<T> {
	#[inline]
	fn eq(&self, other: &Self) -> bool {
		PartialEq::eq(&**self, &**other)
	}
}

impl<T: ?Sized + PartialOrd> PartialOrd for CBox<T> {
	#[inline]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		PartialOrd::partial_cmp(&**self, &**other)
	}
}

impl<T: ?Sized + Ord> Ord for CBox<T> {
	#[inline]
	fn cmp(&self, other: &Self) -> Ordering {
		Ord::cmp(&**self, &**other)
	}
}

impl<T: ?Sized + Eq> Eq for CBox<T> {}

impl<T: ?Sized + Hash> Hash for CBox<T> {
	fn hash<H: Hasher>(&self, state: &mut H) {
		(**self).hash(state);
	}
}

impl<T: ?Sized> borrow::Borrow<T> for CBox<T> {
	fn borrow(&self) -> &T {
		&**self
	}
}

impl<T: ?Sized> borrow::BorrowMut<T> for CBox<T> {
	fn borrow_mut(&mut self) -> &mut T {
		&mut **self
	}
}

impl<T: ?Sized> AsRef<T> for CBox<T> {
	fn as_ref(&self) -> &T {
		&**self
	}
}

impl<T: ?Sized> AsMut<T> for CBox<T> {
	fn as_mut(&mut self) -> &mut T {
		&mut **self
	}
}

/// Propagate `Send` from `T` as we provide roughly the same guarantees as `Box`
unsafe impl<T: ?Sized + Send> Send for CBox<T> {}
/// Propagate `Sync` from `T` as we provide roughly the same guarantees as `Box`
unsafe impl<T: ?Sized + Sync> Sync for CBox<T> {}

#[cfg(test)]
mod tests {
	use std::mem::size_of;
	use std::ptr::null_mut;
	use super::*;

	/// Check if object and pointer sizes match
	#[test]
	fn test_sizes() {
		assert_eq!(size_of::<CBox<()>>(), size_of::<*const ()>());
		assert_eq!(size_of::<CBox<()>>(), size_of::<*mut ()>());
		assert_eq!(size_of::<CBox<c_void>>(), size_of::<*mut c_void>());
		assert_eq!(size_of::<CBox<[i32]>>(), size_of::<*mut [i32]>());
		assert_eq!(size_of::<CBox<[i32; 3]>>(), size_of::<*mut [i32; 3]>());
	}
	
	/// Check if a simple object can be allocated
	#[test]
	fn test_allocation() {
		let mut b: CBox<i32> = CBox::new(32);
		assert_eq!(*b, 32);
		*b = 42;
		assert_eq!(*b, 42);
		drop(b);
	}

	/// Check if conversion from a null pointer panics.
	#[test]
	#[should_panic = "from null pointer"]
	fn test_null() {
		let _: CBox<()> = unsafe { CBox::from_raw(null_mut()) };
	}

	/// Check if slice conversion from a null pointer panics.
	#[test]
	#[should_panic = "from null pointer"]
	fn test_null_slice() {
		let _: CBox<[()]> = unsafe { CBox::from_raw_slice(null_mut(), 1) };
	}

	/// Check if a boxed slice can be created, is correctly zero-initialized
	/// and is correctly modifiable.
	#[test]
	fn test_slice() {
		let uninit_b: CBox<[MaybeUninit<u64>]> = CBox::new_zeroed_slice(3);
		let mut b = unsafe { uninit_b.assume_all_init() };
		assert_eq!(*b, [0, 0, 0]);
		b[1] = u64::MAX;
		assert_eq!(*b, [0, u64::MAX, 0]);
	}
}
