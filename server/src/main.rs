use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt;
use quinn::{
    Certificate, CertificateChain, Endpoint, Incoming, PrivateKey, ServerConfig,
    ServerConfigBuilder, TransportConfig,
};

pub fn make_server_endpoint(bind_addr: SocketAddr) -> anyhow::Result<(Incoming, Vec<u8>)> {
    let (server_config, server_cert) = configure_server()?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);
    let (_endpoint, incoming) = endpoint_builder.bind(&bind_addr)?;
    Ok((incoming, server_cert))
}

fn configure_server() -> anyhow::Result<(ServerConfig, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey::from_der(&priv_key)?;

    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_uni_streams(0).unwrap();
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut cfg_builder = ServerConfigBuilder::new(server_config);
    let cert = Certificate::from_der(&cert_der)?;
    cfg_builder.certificate(CertificateChain::from_certs(vec![cert]), priv_key)?;

    Ok((cfg_builder.build(), cert_der))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server_addr = "127.0.0.1:5000".parse().unwrap();
    let (mut incoming, _server_cert) = make_server_endpoint(server_addr)?;
    // accept a single connection
    let incoming_conn = incoming.next().await.unwrap();
    let new_conn = incoming_conn.await.unwrap();
    println!(
        "[server] connection accepted: addr={}",
        new_conn.connection.remote_address()
    );
    Ok(())
}
