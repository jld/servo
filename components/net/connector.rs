/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use hyper::client::Pool;
use hyper::net::HttpsConnector;
use std::sync::Arc;
use tls::ServoSslClient;

pub type Connector = HttpsConnector<ServoSslClient>;

pub fn create_http_connector() -> Arc<Pool<Connector>> {
    let connector = HttpsConnector::new(ServoSslClient::new());

    Arc::new(Pool::with_connector(Default::default(), connector))
}
