//! DNS resolver for Hyper

#[macro_use]
extern crate log;
extern crate futures;
extern crate hyper;
extern crate rand;
extern crate tokio_core;
extern crate tokio_reactor;
extern crate trust_dns;

use futures::future;
use futures::future::Future;
use hyper::client::{Connect, Service};
use hyper::Uri;
use rand::Rng;
use std::io;
use std::time::Duration;
use trust_dns::client::ClientHandle;

/// Docs
#[derive(Debug, Clone)]
pub enum RecordType {
    /// A
    A,
    /// SRV
    SRV,
    /// AUTO
    AUTO,
}

/// A connector that wraps another connector and provides custom DNS resolution.
#[derive(Debug, Clone)]
pub struct DnsConnector<C> {
    connector: C,
    record_type: RecordType,
    dns_addr: std::net::SocketAddr,
}

impl<C> DnsConnector<C>
where
    C: Connect,
{
    pub fn new(dns_addr: std::net::SocketAddr, connector: C) -> DnsConnector<C> {
        Self::new_with_resolve_type(dns_addr, connector, RecordType::AUTO)
    }

    /// Docs
    pub fn new_with_resolve_type(
        dns_addr: std::net::SocketAddr,
        connector: C,
        record_type: RecordType,
    ) -> DnsConnector<C> {
        DnsConnector {
            connector: connector,
            record_type: record_type,
            dns_addr: dns_addr,
        }
    }
}

impl<C> Service for DnsConnector<C>
where
    C: Service<Request = Uri, Error = io::Error> + 'static,
    C: Clone,
{
    type Request = C::Request;
    type Response = C::Response;
    type Error = C::Error;
    type Future =
        Box<Future<Item = <C::Future as Future>::Item, Error = <C::Future as Future>::Error>>;

    fn call(&self, uri: Uri) -> Self::Future {
        let connector = self.connector.clone();

        // We would expect a DNS request to be responded to quickly, but add a timeout
        // to ensure that we don't wait for ever if the DNS server does not respond.
        let timeout = Duration::from_millis(30000);

        let (stream, sender) =
            trust_dns::tcp::TcpClientStream::with_timeout(self.dns_addr, timeout);

        let dns_client = trust_dns::client::ClientFuture::new(stream, sender, None);

        // Check if this is a domain name or not before trying to use DNS resolution.
        match uri.host().unwrap().to_string().parse() {
            Ok(std::net::Ipv4Addr { .. }) => {
                // Nothing to do, so just pass it along to the main connector
                Box::new(connector.call(uri.clone()))
            }
            Err(_) => {
                let port = uri.port().clone();
                let scheme = uri.scheme().unwrap().to_string();
                let host = uri.host().unwrap().to_string();

                debug!("Trying to resolve {}://{}", scheme, &host);

                // Add a `.` to the end of the host so that we can query the domain records.
                let name = trust_dns::rr::Name::parse(&format!("{}.", host), None).unwrap();

                let trust_record_type = match self.record_type {
                    RecordType::A => trust_dns::rr::RecordType::A,
                    RecordType::SRV => trust_dns::rr::RecordType::SRV,
                    RecordType::AUTO => {
                        // If the port is not provided, then and perform SRV lookup, otherwise lookup
                        // A records.
                        if port.is_none() {
                            trust_dns::rr::RecordType::SRV
                        } else {
                            debug!("Using A record lookup for: {}", &host);
                            trust_dns::rr::RecordType::A
                        }
                    }
                };

                debug!("Sending DNS request");

                let name_clone = name.clone();

                let future = dns_client
                    .and_then(move |mut client| {
                        client.query(
                            name_clone.clone(),
                            trust_dns::rr::DNSClass::IN,
                            trust_record_type,
                        )
                    })
                    .or_else(|_| {
                        return future::err(
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "Failed to query DNS server",
                            ).into(),
                        );
                    })
                    .and_then(move |res| {
                        let answers = res.answers();

                        if answers.is_empty() {
                            return future::err(
                                std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "No valid DNS answers",
                                ).into(),
                            );
                        }

                        let mut rng = rand::thread_rng();

                        // First find the SRV records if they were requested
                        let (target, a_records, new_port) = if let trust_dns::rr::RecordType::SRV =
                            trust_record_type
                        {
                            let answer = rng.choose(answers).expect("Sort out what to return here");

                            let srv = match *answer.rdata() {
                                trust_dns::rr::RData::SRV(ref srv) => srv,
                                _ => {
                                    return future::err(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            "Unexpected DNS response",
                                        ).into(),
                                    )
                                }
                            };

                            (srv.target().clone(), res.additionals(), Some(srv.port()))
                        } else {
                            // For A record requests it is the domain name that
                            // we want to use.
                            (name.clone(), answers, port)
                        };

                        let entry = a_records.iter().find(|record| record.name() == &target);

                        if let Some(entry) = entry {
                            let addr = match *entry.rdata() {
                                trust_dns::rr::RData::A(ref addr) => addr,
                                _ => {
                                    return future::err(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            "Did not receive a valid record",
                                        ).into(),
                                    )
                                }
                            };

                            future::ok((addr.to_string(), new_port))
                        } else {
                            return future::err(
                                std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "Did not receive a valid record",
                                ).into(),
                            );
                        }
                    })
                    .and_then(move |(ip, port)| {
                        let new_uri_str = if let Some(port) = port {
                            format!("{}://{}:{}", scheme, &ip, port)
                        } else {
                            format!("{}://{}", scheme, &ip)
                        };

                        debug!("Resolved request to {}", &new_uri_str);

                        let new_uri = new_uri_str.parse::<Uri>().unwrap();

                        connector.call(new_uri)
                    });

                Box::new(future)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
