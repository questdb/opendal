// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use http::Uri;
use http::response::Parts;

use crate::Error;
use crate::ErrorKind;

/// Create a new error happened during building request.
pub fn new_request_build_error(err: http::Error) -> Error {
    Error::new(ErrorKind::Unexpected, "building http request")
        .with_operation("http::Request::build")
        .set_source(err)
}

/// Create a new error happened during signing request.
pub fn new_request_credential_error(err: anyhow::Error) -> Error {
    Error::new(
        ErrorKind::Unexpected,
        "loading credential to sign http request",
    )
    .set_temporary()
    .with_operation("reqsign::LoadCredential")
    .set_source(err)
}

/// Create a new error happened during signing request.
pub fn new_request_sign_error(err: anyhow::Error) -> Error {
    Error::new(ErrorKind::Unexpected, "signing http request")
        .with_operation("reqsign::Sign")
        .set_source(err)
}

/// Add response context to error.
///
/// This helper function will:
///
/// - remove sensitive or useless headers from parts.
/// - add the redacted request URI if parts extensions contains `Uri`.
pub fn with_error_response_context(mut err: Error, mut parts: Parts) -> Error {
    if let Some(uri) = parts.extensions.get::<Uri>() {
        err = err.with_context("uri", crate::HttpUri::new(uri.to_string()).redacted_uri());
    }

    // The following headers may contains sensitive information.
    parts.headers.remove("Set-Cookie");
    parts.headers.remove("WWW-Authenticate");
    parts.headers.remove("Proxy-Authenticate");
    // GCS echoes the resumable upload session credential in this header.
    parts.headers.remove("x-guploader-uploadid");

    if parts.headers.contains_key(http::header::LOCATION) {
        let location = crate::HttpUri::from_response_location(&mut parts)
            .map(|uri| uri.redacted_uri())
            .unwrap_or("<invalid URL>")
            .parse()
            .unwrap_or_else(|_| http::HeaderValue::from_static("<invalid URL>"));
        parts.headers.insert(http::header::LOCATION, location);
    }

    err = err.with_context("response", format!("{parts:?}"));

    err
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_context_redacts_session_credentials() {
        let uri = "https://storage.googleapis.com/upload/storage/v1/b/bucket/o?uploadType=resumable&name=a%2Fb&upload_id=session-secret";
        let response = http::Response::builder()
            .status(503)
            .extension(uri.parse::<Uri>().unwrap())
            .header(http::header::LOCATION, uri)
            .header("X-GUploader-UploadID", "session-secret")
            .header("x-guploader-uploadid", "second-session-secret")
            .header("x-request-id", "request-123")
            .body(())
            .unwrap();
        let (parts, ()) = response.into_parts();
        let error = with_error_response_context(
            Error::new(ErrorKind::Unexpected, "backend unavailable").set_temporary(),
            parts,
        );
        assert_eq!(error.kind(), ErrorKind::Unexpected);
        assert!(error.is_temporary());
        for diagnostic in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!diagnostic.contains("session-secret"), "{diagnostic}");
            assert!(diagnostic.contains("upload_id=[REDACTED]"));
            assert!(diagnostic.contains("name=a%2Fb"));
            assert!(diagnostic.contains("request-123"));
            assert!(diagnostic.contains("503"));
            assert!(diagnostic.contains("backend unavailable"));
        }
    }
}
