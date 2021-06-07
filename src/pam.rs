use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::ptr::NonNull;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
#[non_exhaustive]
pub enum AuthenticateError {
    AuthError,
    InsufficientCredentials,
    AuthInfoUnavailable,
    UnknownUser,
    MaxTries,
}

impl Into<c_int> for AuthenticateError {
    #[inline]
    fn into(self) -> c_int {
        match self {
            Self::AuthError => pam_sys::PAM_AUTH_ERR,
            Self::InsufficientCredentials => pam_sys::PAM_CRED_INSUFFICIENT,
            Self::AuthInfoUnavailable => pam_sys::PAM_AUTHINFO_UNAVAIL,
            Self::UnknownUser => pam_sys::PAM_USER_UNKNOWN,
            Self::MaxTries => pam_sys::PAM_MAXTRIES,
        }
    }
}

impl fmt::Display for AuthenticateError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AuthError => "authentication error",
            Self::InsufficientCredentials => "insufficient credentials",
            Self::AuthInfoUnavailable => "authentication info unavailable",
            Self::UnknownUser => "unknown user",
            Self::MaxTries => "max tries exceeded",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AuthenticateError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemError {
    BadItem,
    BufferError,
    PermissionDenied,
    SystemError,
    Unknown,
}

impl From<c_int> for ItemError {
    #[inline]
    fn from(val: c_int) -> Self {
        match val {
            pam_sys::PAM_BAD_ITEM => Self::BadItem,
            pam_sys::PAM_BUF_ERR => Self::BufferError,
            pam_sys::PAM_PERM_DENIED => Self::PermissionDenied,
            pam_sys::PAM_SYSTEM_ERR => Self::SystemError,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for ItemError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BadItem => "inaccessible item",
            Self::BufferError => "internal buffer error",
            Self::PermissionDenied => "permission denied",
            Self::SystemError => "bad handle",
            Self::Unknown => "unknown error",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ItemError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetAuthTokenError {
    Auth,
    AuthToken,
    System,
    TryAgain,
    Unknown,
}

impl From<c_int> for GetAuthTokenError {
    #[inline]
    fn from(val: c_int) -> Self {
        match val {
            pam_sys::PAM_AUTH_ERR => Self::Auth,
            pam_sys::PAM_AUTHTOK_ERR => Self::AuthToken,
            pam_sys::PAM_SYSTEM_ERR => Self::System,
            pam_sys::PAM_TRY_AGAIN => Self::TryAgain,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for GetAuthTokenError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Auth => "cannot retrieve authentication token",
            Self::AuthToken => "cannot retrieve new authentication token",
            Self::System => "no space for authentication token",
            Self::TryAgain => "authentication token mismatch",
            Self::Unknown => "unknown error",
        };
        f.write_str(s)
    }
}

impl std::error::Error for GetAuthTokenError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetUserError {
    System,
    Conversation,
    Buffer,
    Aborted,
    ConversationTryAgain,
    Unknown,
}

impl From<c_int> for GetUserError {
    #[inline]
    fn from(val: c_int) -> Self {
        match val {
            pam_sys::PAM_SYSTEM_ERR => Self::System,
            pam_sys::PAM_CONV_ERR => Self::Conversation,
            pam_sys::PAM_BUF_ERR => Self::Buffer,
            pam_sys::PAM_ABORT => Self::Aborted,
            pam_sys::PAM_CONV_AGAIN => Self::ConversationTryAgain,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for GetUserError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::System => "bad handle",
            Self::Conversation => "failed to retrieve username",
            Self::Buffer => "internal buffer error",
            Self::Aborted => "failed to resume conversation",
            Self::ConversationTryAgain => "conversation is waiting for an event",
            Self::Unknown => "unknown error",
        };
        f.write_str(s)
    }
}

impl std::error::Error for GetUserError {}

/// Wrapper for a PAM handle.
pub struct Handle(NonNull<pam_sys::pam_handle_t>);

impl Handle {
    /// Create a new `Handle` with a raw pointer.
    ///
    /// # Safety
    /// `pamh` should be a valid pointer to `pam_handle_t`.
    #[inline(always)]
    pub unsafe fn new(pamh: *mut pam_sys::pam_handle_t) -> Self {
        Self(NonNull::new_unchecked(pamh))
    }

    /// Get the username to authenticate, prompting the user if necessary.
    ///
    /// Corresponds to Linux-PAM API `pam_get_user`.
    pub fn get_user(&self, prompt: Option<&CStr>) -> Result<&CStr, GetUserError> {
        let mut out: *const c_char = std::ptr::null();
        let prompt = prompt.map(|s| s.as_ptr()).unwrap_or_else(std::ptr::null);
        let ret = unsafe {
            let ret = pam_sys::pam_get_user(
                self.0.as_ptr(),
                &mut out,
                prompt,
            );
            if ret != pam_sys::PAM_SUCCESS {
                return Err(GetUserError::from(ret));
            }
            // out is valid here
            CStr::from_ptr(out)
        };
        Ok(ret)
    }

    /// Get the authentication token, prompting the user if necessary.
    ///
    /// Corresponds to Linux-PAM API `pam_get_authtok`.
    pub fn get_auth_token(&self, prompt: Option<&CStr>) -> Result<&CStr, GetAuthTokenError> {
        let mut out: *const c_char = std::ptr::null();
        let prompt = prompt.map(|s| s.as_ptr()).unwrap_or_else(std::ptr::null);
        let ret = unsafe {
            let ret = pam_sys::pam_get_authtok(
                self.0.as_ptr(),
                pam_sys::PAM_AUTHTOK,
                &mut out,
                prompt,
            );
            if ret != pam_sys::PAM_SUCCESS {
                return Err(GetAuthTokenError::from(ret));
            }
            // out is valid here
            CStr::from_ptr(out)
        };
        Ok(ret)
    }
}
