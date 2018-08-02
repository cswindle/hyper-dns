//! DNS resolver for Hyper

#[macro_use]
extern crate log;
extern crate hyper;
extern crate rand;
extern crate tokio_core;
extern crate trust_dns;

use trust_dns::client::ClientHandle;
use rand::Rng;
use hyper::net::{NetworkConnector, NetworkStream};
use std::time::Duration;
use tokio_reactor::Handle;

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
pub struct DnsConnector<T, S> {
    connector: T,
    record_type: RecordType,
    dns_client: trust_dns::client::ClientFuture<S>,
    force_https: bool,
}

impl<T, S> DnsConnector<T, S>
where T: Connect
{
    pub fn new(dns_addr: std::net::SocketAddr, connector: C) -> DnsConnector<C> {
        Self::new_with_resolve_type(dns_addr, connector, RecordType::AUTO)
    }

    /// Docs
    pub fn new_with_resolve_type(dns_addr: std::net::SocketAddr,
                                 connector: C,
                                 record_type: RecordType)
                                 -> DnsConnector<C> {

        let handle = Handle::default();

        let (stream, sender) = trust_dns::tcp::TcpClientStream::new(dns_addr, &handle);

        // We would expect a DNS request to be responded to quickly, but add a timeout
        // to ensure that we don't wait for ever if the DNS server does not respond.
        let timeout = Duration::from_millis(30000);
        let mut dns_client =
            trust_dns::client::ClientFuture::with_timeout(
                stream,
                sender,
                &handle,
                timeout,
                None);

        DnsConnector {
            connector: connector,
            record_type: record_type,
            dns_client: dns_client,
            force_https: true,
        }
    }
}

impl<T, S> Connect for DnsConnector<T, S>
where T: Connect<Error=io::Error>,
      T::Transport: 'static,
      T::Future: 'static,
{
    type Transport = T::Transport;
    type Error = io::Error;
    type Future = T::Future;

    fn connect(&self, dst: Destination) -> Self::Future {

        let connector = self.connector.clone();
        let force_https = self.force_https;

        // Check if this is a domain name or not before trying to use DNS resolution.

        let (dst.host(), dst.port()) = match dst.host().parse() {
            Ok(std::net::Ipv4Addr { .. }) => {
                // Nothing to do, so just pass it along to the main connector
                connector.connect(dst)
            }
            Err(_) => {
                debug!("Trying to resolve {}://{}", scheme, &host);

                // Add a `.` to the end of the host so that we can query the domain records.
                let name = trust_dns::rr::Name::parse(&format!("{}.", host), None).unwrap();

                let trust_record_type = match self.record_type {
                    RecordType::A => trust_dns::rr::RecordType::A,
                    RecordType::SRV => trust_dns::rr::RecordType::SRV,
                    RecordType::AUTO => {
                        // If the port is a standard HTTP port (80, or 443), then assume
                        // one was not provided and perform SRV lookup, otherwise lookup
                        // A records.
                        if (port == 80) || (port == 443) {
                            trust_dns::rr::RecordType::SRV
                        } else {
                            debug!("Using A record lookup for: {}", &host);
                            trust_dns::rr::RecordType::A
                        }
                    }
                };

                debug!("Sending DNS request");

                dns_client
                    .query(name.clone(),
                           trust_dns::rr::DNSClass::IN,
                           trust_record_type)
                    .and_then(|res| {
                        let answers = res.answers();

                        if answers.is_empty() {
                            return err(std::io::Error::new(std::io::ErrorKind::Other,
                                                           "No valid DNS answers")
                                               .into());
                        }

                        let mut rng = rand::thread_rng();

                        // First find the SRV records if they were requested
                        let (target, a_records, new_port) = if let trust_dns::rr::RecordType::SRV =
                            trust_record_type {
                            let answer = rng.choose(answers).expect("Sort out what to return here");

                            let srv = match *answer.rdata() {
                                trust_dns::rr::RData::SRV(ref srv) => srv,
                                _ => {
                                    return err(std::io::Error::new(std::io::ErrorKind::Other,
                                                                   "Unexpected DNS response")
                                                       .into())
                                }
                            };

                            (srv.target(), res.additionals(), srv.port())
                        } else {
                            // For A record requests it is the domain name that
                            // we want to use.
                            (&name, answers, port)
                        };

                        let entry = a_records.iter().find(|record| record.name() == target);

                        if let Some(entry) = entry {
                            let addr = match *entry.rdata() {
                                trust_dns::rr::RData::A(ref addr) => addr,
                                _ => {
                                    return err(std::io::Error::new(std::io::ErrorKind::Other,
                                                                   "Did not receive a valid record")
                                                       .into())
                                }
                            };

                            (addr.to_string(), new_port)
                        } else {
                            return err(std::io::Error::new(std::io::ErrorKind::Other,
                                                           "Did not receive a valid record")
                                               .into());
                        }
                    })
                    .and_then(|ip, port| {
                        debug!("Resolved request to {}://{}:{}", scheme, &host, port);

                        let mut new_dst = dst.clone();
                        new_dst.set_host(ip);
                        new_dst.set_port(port);
                        connector.connect(new_dst)
                    })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
