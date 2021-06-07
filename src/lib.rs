#[macro_use] extern crate log;

use std::ffi::{CStr, OsStr};
use std::os::raw::{c_int, c_char};
use std::os::unix::ffi::OsStrExt;

mod pam;

#[derive(Debug)]
struct Params<'a> {
    login_endpoint: &'a str,
    secret_key_path: &'a OsStr,
    publickey_only: bool,
}

#[derive(Debug, serde::Serialize)]
struct AuthPayload<'a> {
    username: &'a str,
    password: &'a str,
}

impl<'a> Params<'a> {
    fn parse(args: &[&'a CStr]) -> Result<Self, pam::AuthenticateError> {
        let mut login_endpoint = None;
        let mut secret_key_path = OsStr::from_bytes(b"/etc/bacchus/keypair/tweetnacl");
        let mut publickey_only = false;
        for &arg in args {
            let b = arg.to_bytes();
            if b.len() >= 4 && &b[..4] == b"url=" {
                login_endpoint = Some(&arg[4..]);
            } else if b.len() >= 4 && &b[..4] == b"key=" {
                secret_key_path = OsStr::from_bytes(&b[4..]);
            } else if b == b"publickey_only" {
                publickey_only = true;
            }
        }

        let login_endpoint = match login_endpoint {
            Some(ep) => {
                ep.to_str()
                    .map_err(|_| {
                        error!("Failed to parse arguments: login endpoint is not in UTF-8");
                        pam::AuthenticateError::AuthInfoUnavailable
                    })?
            },
            None => {
                error!("Login endpoint not set");
                return Err(pam::AuthenticateError::AuthInfoUnavailable);
            },
        };
        Ok(Self {
            login_endpoint,
            secret_key_path,
            publickey_only,
        })
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::pam_handle_t,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char
) -> c_int
{
    let ret = std::panic::catch_unwind(move || {
        let formatter = syslog::Formatter3164 {
            facility: syslog::Facility::LOG_AUTH,
            hostname: None,
            process: String::from("pam_bacchus"),
            pid: 0,
        };
        match syslog::unix(formatter) {
            Ok(logger) => {
                if log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger))).is_ok() {
                    log::set_max_level(log::LevelFilter::Info);
                }
            }
            _ => {}
        }

        let args = std::slice::from_raw_parts(argv, argc as usize)
            .iter()
            .map(|&ptr| CStr::from_ptr(ptr))
            .collect::<Vec<_>>();
        let mut handle = pam::Handle::new(pamh);

        authenticate(&mut handle, flags, &args)
            .map(|_| pam_sys::PAM_SUCCESS)
            .unwrap_or_else(<_ as Into<c_int>>::into)
    });

    match ret {
        Ok(ret) => ret,
        Err(_) => {
            error!("pam_sm_authenticate panicked");
            pam_sys::PAM_AUTH_ERR
        },
    }
}

fn authenticate(handle: &mut pam::Handle, flags: c_int, args: &[&CStr]) -> Result<(), pam::AuthenticateError> {
    let params = Params::parse(args)?;
    let key = std::fs::File::open(params.secret_key_path)
        .and_then(|mut f| {
            let mut key = [0u8; 64];
            std::io::Read::read_exact(&mut f, &mut key)?;
            Ok(key)
        })
        .map_err(|e| {
            error!("Failed to read secret key: {}", e);
        })
        .ok();
    if key.is_none() && params.publickey_only {
        error!("Public key auth enforced, aborting");
        return Err(pam::AuthenticateError::AuthInfoUnavailable);
    } else {
        warn!("Falling back to IP address auth");
    }

    let username = handle.get_user(None)
        .map_err(|e| {
            error!("Failed to get username: {}", e);
            pam::AuthenticateError::AuthError
        })
        .and_then(|username| {
            username.to_str()
                .map_err(|_| {
                    error!("Failed to parse username: not in UTF-8");
                    pam::AuthenticateError::AuthError
                })
        })?;
    let password = handle.get_auth_token(None)
        .map_err(|e| {
            error!("Failed to get token: {}", e);
            pam::AuthenticateError::AuthError
        })
        .and_then(|password| {
            password.to_str()
                .map_err(|_| {
                    error!("Failed to parse token: not in UTF-8");
                    pam::AuthenticateError::AuthError
                })
        })?;

    if flags & pam_sys::PAM_DISALLOW_NULL_AUTHTOK != 0 && password.is_empty() {
        error!("Authentication failed: null tokens are not allowed");
        return Err(pam::AuthenticateError::AuthError);
    }

    let payload = AuthPayload { username, password };
    let body = serde_json::to_string(&payload)
        .map_err(|e| {
            error!("Failed to serialize auth payload: {}", e);
            pam::AuthenticateError::AuthError
        })?;

    let mut req = isahc::Request::post(params.login_endpoint)
        .header("user-agent", "pam_bacchus/0.2")
        .header("content-type", "application/json")
        .header("accept", "application/json");
    if let Some(secret_key) = key {
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&secret_key[32..]);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Time before UNIX epoch")
            .as_secs();
        let header_pubkey = base64::encode(&public_key);
        let message = format!("{}{}", timestamp, body).into_bytes();
        let mut signed_message = vec![0u8; message.len() + 64];
        tweetnacl::sign(&mut signed_message, &message, &secret_key);
        let header_signature = base64::encode(&signed_message[..64]);

        req = req
            .header("x-bacchus-id-pubkey", header_pubkey)
            .header("x-bacchus-id-timestamp", timestamp.to_string())
            .header("x-bacchus-id-signature", header_signature);
    }
    let req = req.body(body)
        .map_err(|e| {
            error!("Failed to create request: {}", e);
            pam::AuthenticateError::AuthError
        })?;

    let resp = isahc::HttpClient::new()
        .and_then(move |client| client.send(req))
        .map_err(|e| {
            error!("Failed to send request: {}", e);
            pam::AuthenticateError::AuthError
        })?;

    let status = resp.status();
    if status != isahc::http::StatusCode::OK {
        warn!("Authentication failed for user {}: {}", username, status);
        Err(pam::AuthenticateError::AuthError)
    } else {
        Ok(())
    }
}