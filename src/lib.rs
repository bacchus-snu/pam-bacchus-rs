#[cfg(not(target_os = "linux"))]
compile_error!("pam_bacchus is a Linux-PAM module, hence not compatible with non-Linux targets.");

#[macro_use] extern crate log;

use std::ffi::CStr;
use std::os::raw::{c_int, c_char};

mod pam;
mod params;

#[derive(Debug, serde::Serialize)]
struct AuthPayload<'a> {
    username: &'a str,
    password: &'a str,
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_sys::pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char
) -> c_int
{
    pam_sys::PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_sys::pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char
) -> c_int
{
    pam_sys::PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::pam_handle_t,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char
) -> c_int
{
    let silent = flags & pam_sys::PAM_SILENT != 0;
    let ret = std::panic::catch_unwind(move || {
        if !silent {
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
    let params = params::Params::from_args(args)?;
    let key = std::fs::File::open(params.secret_key_path())
        .and_then(|mut f| {
            let mut key = [0u8; 64];
            std::io::Read::read_exact(&mut f, &mut key)?;
            Ok(key)
        })
        .map_err(|e| {
            error!("Failed to read secret key: {}", e);
        })
        .ok();
    if key.is_none() && params.publickey_only() {
        error!("Public key auth enforced, aborting");
        return Err(pam::AuthenticateError::AuthInfoUnavailable);
    } else if key.is_none() {
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

    let mut curl_handle = curl::easy::Easy::new();
    curl_handle.url(params.login_endpoint())
        .map_err(|e| {
            error!("Invalid endpoint URL: {}", e);
            pam::AuthenticateError::AuthInfoUnavailable
        })?;
    curl_handle.post_fields_copy(body.as_bytes()).unwrap();

    let mut headers = curl::easy::List::new();
    headers.append("user-agent: pam_bacchus/0.2").unwrap();
    headers.append("content-type: application/json").unwrap();
    headers.append("accept: application/json").unwrap();

    if let Some(secret_key) = key {
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&secret_key[32..]);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Time before UNIX epoch")
            .as_secs();
        headers.append(&format!("x-bacchus-id-timestamp: {}", timestamp)).unwrap();

        let mut header_pubkey = String::from("x-bacchus-id-pubkey: ");
        base64::encode_config_buf(&public_key, base64::STANDARD, &mut header_pubkey);
        headers.append(&header_pubkey).unwrap();

        let message = format!("{}{}", timestamp, body).into_bytes();
        let mut signed_message = vec![0u8; message.len() + 64];
        tweetnacl::sign(&mut signed_message, &message, &secret_key);

        let mut header_signature = String::from("x-bacchus-id-signature: ");
        base64::encode_config_buf(&signed_message[..64], base64::STANDARD, &mut header_signature);
        headers.append(&header_signature).unwrap();
    }
    curl_handle.http_headers(headers).unwrap();

    curl_handle.perform()
        .map_err(|e| {
            error!("Failed to send request: {}", e);
            pam::AuthenticateError::AuthError
        })?;

    let status = curl_handle.response_code().unwrap();
    if status != 200 {
        warn!("Authentication failed for user {}: status code {}", username, status);
        Err(pam::AuthenticateError::AuthError)
    } else {
        Ok(())
    }
}
