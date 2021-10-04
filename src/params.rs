use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;

use crate::pam::AuthenticateError;

#[derive(Debug)]
pub struct Params<'a> {
    login_endpoint: &'a str,
    socket_path: &'a OsStr,
    publickey_only: bool,
}

impl<'a> Params<'a> {
    pub fn from_args(args: &[&'a CStr]) -> Result<Self, AuthenticateError> {
        let mut login_endpoint = None;
        let mut socket_path = OsStr::from_bytes(b"/run/bacchus-sign.sock");
        let mut publickey_only = false;
        for &arg in args {
            let b = arg.to_bytes();
            if b.len() >= 4 && &b[..4] == b"url=" {
                login_endpoint = Some(&arg[4..]);
            } else if b.len() >= 4 && &b[..4] == b"sock=" {
                socket_path = OsStr::from_bytes(&b[4..]);
            } else if b == b"publickey_only" {
                publickey_only = true;
            }
        }

        let login_endpoint = match login_endpoint {
            Some(ep) => ep.to_str().map_err(|_| {
                error!("Failed to parse arguments: login endpoint is not in UTF-8");
                AuthenticateError::AuthInfoUnavailable
            })?,
            None => {
                error!("Login endpoint not set");
                return Err(AuthenticateError::AuthInfoUnavailable);
            }
        };
        Ok(Self {
            login_endpoint,
            socket_path,
            publickey_only,
        })
    }

    #[inline(always)]
    pub fn login_endpoint(&self) -> &str {
        self.login_endpoint
    }

    #[inline(always)]
    pub fn socket_path(&self) -> &std::path::Path {
        self.socket_path.as_ref()
    }

    #[inline(always)]
    pub fn publickey_only(&self) -> bool {
        self.publickey_only
    }
}
