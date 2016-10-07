extern crate openssl;
extern crate openssl_verify;

use hyper::net::{SslClient, HttpStream};
use self::openssl::ssl::{SSL_OP_NO_COMPRESSION, SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3, SSL_VERIFY_PEER};
use self::openssl::ssl::{Ssl, SslContext, SslMethod, SslStream};
use self::openssl::ssl::error::{OpensslError, SslError};
use std::error::Error;
use std::sync::Arc;
use util::resource_files::resources_dir_path;

// The basic logic here is to prefer ciphers with ECDSA certificates, Forward
// Secrecy, AES GCM ciphers, AES ciphers, and finally 3DES ciphers.
// A complete discussion of the issues involved in TLS configuration can be found here:
// https://wiki.mozilla.org/Security/Server_Side_TLS
const DEFAULT_CIPHERS: &'static str = concat!(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:",
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:",
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:",
    "ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:",
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:",
    "ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:",
    "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
);

pub struct ServoSslClient {
    context: Arc<SslContext>,
}

impl ServoSslClient {
    pub fn new() -> Self {
        let mut context = SslContext::new(SslMethod::Sslv23).unwrap();
        context.set_CA_file(&resources_dir_path()
                            .expect("Need certificate file to make network requests")
                            .join("certs")).unwrap();
        context.set_cipher_list(DEFAULT_CIPHERS).unwrap();
        context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
        ServoSslClient {
            context: Arc::new(context)
        }
    }
}

impl SslClient for ServoSslClient {
    type Stream = SslStream<HttpStream>;

    fn wrap_client(&self, stream: HttpStream, host: &str)
                   -> Result<Self::Stream, ::hyper::Error> {
        let mut ssl = try!(Ssl::new(&self.context));
        try!(ssl.set_hostname(host));
        let host = host.to_owned();
        ssl.set_verify_callback(SSL_VERIFY_PEER, move |p, x| {
            openssl_verify::verify_callback(&host, p, x)
        });
        SslStream::connect(ssl, stream).map_err(From::from)
    }
}

pub fn explain_tls_error(error: &(Error + Send + 'static)) -> Option<String> {
    if let Some(&SslError::OpenSslErrors(ref errors)) = error.downcast_ref::<SslError>() {
        if errors.iter().any(is_cert_verify_error) {
            let mut error_report = vec![format!("ssl error ({}):", openssl::version::version())];
            let mut suggestion = None;
            for err in errors {
                if is_unknown_message_digest_err(err) {
                    suggestion = Some("<b>Servo recommends upgrading to a newer OpenSSL version.</b>");
                }
                error_report.push(format_ssl_error(err));
            }

            if let Some(suggestion) = suggestion {
                error_report.push(suggestion.to_owned());
            }

            return Some(error_report.join("<br>\n"));
        }
    }
    None
}

// FIXME: This incredibly hacky. Make it more robust, and at least test it.
fn is_cert_verify_error(error: &OpensslError) -> bool {
    match error {
        &OpensslError::UnknownError { ref library, ref function, ref reason } => {
            library == "SSL routines" &&
            function.to_uppercase() == "SSL3_GET_SERVER_CERTIFICATE" &&
            reason == "certificate verify failed"
        }
    }
}

fn is_unknown_message_digest_err(error: &OpensslError) -> bool {
    match error {
        &OpensslError::UnknownError { ref library, ref function, ref reason } => {
            library == "asn1 encoding routines" &&
            function == "ASN1_item_verify" &&
            reason == "unknown message digest algorithm"
        }
    }
}

fn format_ssl_error(error: &OpensslError) -> String {
    match error {
        &OpensslError::UnknownError { ref library, ref function, ref reason } => {
            format!("{}: {} - {}", library, function, reason)
        }
    }
}
