/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate nss_hyper;

use self::nss_hyper::NssClient;
use std::error::Error;

pub type ServoSslClient = NssClient;

pub fn explain_tls_error(_error: &(Error + Send + 'static)) -> Option<String> {
    // FIXME
    None
}
