use std::{env, fmt::Debug, io::{BufRead, BufReader}, sync::Arc};

use axum::{routing::post, Router};
use ldap3::LdapConnAsync;

pub mod service;
pub mod handler;
pub mod models;
use openssl::{pkey::PKey, x509::X509};
use rcgen::{Certificate, CertificateParams, Issuer, KeyPair};
use service::ldap_service::LdapService;

use crate::handler::setall_handler::handler;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info,rustapi=debug")
        .init();
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    //                         Pegando Variaveis de Ambiente
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    let addr = match env::var("BIND") {
        Ok(uri) => uri,
        Err(_) => "0.0.0.0:3000".to_string(),
    };

    let ldap_uri = match env::var("LDAP_URI") {
        Ok(uri) => uri,
        Err(_) => "ldap://localhost:389".to_string(),
    };
    
    let base_dn = match env::var("BASE_DN") {
        Ok(value) => value,
        Err(_) => "ou=accounts,dc=domain,dc=com".to_string(),
    };

    let ca_cert_pem = env::var("CA_CART").unwrap();
    let ca_key_pem = env::var("CA_KEY").unwrap();
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    //                                      Dependecies
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    let ca_cert = X509::from_pem(ca_cert_pem.as_bytes())
        .map_err(|e| format!("Failed to parse CA cert PEM: {}", e))?;
    let ca_key = PKey::private_key_from_pem(ca_key_pem.as_bytes())
        .map_err(|e| format!("Failed to parse CA key PEM: {}", e))?; ca_key_pair = KeyPair::from_pem(&ca_key_pem).unwrap();
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    //                                      Conexões
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    let  (conn, ldap) = LdapConnAsync::new(&ldap_uri)
        .await
        .unwrap();
    ldap3::drive!(conn);
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    //                                      Serviços
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    let ldap_service = LdapService::new(ldap, Arc::new(base_dn));
    
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    //                                      Rotas
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    let get_route: Router<LdapService> = axum::Router::new()
        .route("/get", post(handler));
    
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    //                              Juntar Rotas e Escutar
    // ========================================================================================
    // ----------------------------------------------------------------------------------------
    // ========================================================================================
    let routes: Router<LdapService> = Router::new()
        .nest("/api", get_route);
    let app: Router = Router::new()
        .merge(routes)
        .with_state(ldap_service);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap();
    axum::serve(listener, app)
    .await
    .unwrap()
}

/*
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // opcional: carregar .env durante desenvolvimento
    let _ = dotenv::dotenv();

    // Ler as variáveis de ambiente
    let ca_cert_pem = env::var("CA_CERT_PEM")
        .map_err(|_| "CA_CERT_PEM not set in environment")?;
    let ca_key_pem = env::var("CA_KEY_PEM")
        .map_err(|_| "CA_KEY_PEM not set in environment")?;
    // CN do cliente pode vir como argumento ou env
    let client_cn = env::args().nth(1).unwrap_or_else(|| "client1".to_string());

    // Parse da CA
    let ca_cert = X509::from_pem(ca_cert_pem.as_bytes())
        .map_err(|e| format!("Failed to parse CA cert PEM: {}", e))?;
    let ca_key = PKey::private_key_from_pem(ca_key_pem.as_bytes())
        .map_err(|e| format!("Failed to parse CA key PEM: {}", e))?;

    // Gerar chave RSA para o cliente (2048 bits)
    let rsa = Rsa::generate(2048)?;
    let client_key = PKey::from_rsa(rsa)?;

    // Construir o subject do cliente
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COMMONNAME, &client_cn)?;
    let subject_name = name_builder.build();

    // Serial number aleatório
    let mut serial = BigNum::new()?;
    serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;

    // Build do certificado
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?; // X509 v3 (version value is v-1)
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&subject_name)?;
    // issuer = CA subject
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_not_before(&Asn1Time::days_from_now(0)?)?;
    // validade por 1 ano (ajuste conforme necessário)
    builder.set_not_after(&Asn1Time::days_from_now(365)?)?;
    builder.set_pubkey(&client_key)?;

    // Extensions: basicConstraints - not a CA
    let bc = BasicConstraints::new().critical().ca(false).build()?;
    builder.append_extension(bc)?;

    // keyUsage
    let ku = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()?;
    builder.append_extension(ku)?;

    // extendedKeyUsage (clientAuth)
    let eku = ExtendedKeyUsage::new().client_auth().build()?;
    builder.append_extension(eku)?;

    // opcional: SubjectAltName se quiser IPs/DNS (exemplo DNS)
    let san = SubjectAlternativeName::new().dns(&client_cn).build(&builder.x509v3_context(Some(&ca_cert), None))?;
    builder.append_extension(san)?;

    // Assinar com a chave da CA (SHA256)
    builder.sign(&ca_key, MessageDigest::sha256())?;

    let client_cert: X509 = builder.build();

    // Serializar para PEM
    let client_cert_pem = client_cert.to_pem()?;
    let client_key_pem = client_key.private_key_to_pem_pkcs8()?; // PKCS#8, compatível com openvpn

    // Imprimir no stdout (ou salvar em arquivos conforme desejar)
    println!("-----BEGIN CLIENT CERT PEM-----");
    println!("{}", String::from_utf8(client_cert_pem.clone())?);
    println!("-----END CLIENT CERT PEM-----\n");

    println!("-----BEGIN CLIENT KEY PEM-----");
    println!("{}", String::from_utf8(client_key_pem.clone())?);
    println!("-----END CLIENT KEY PEM-----\n");

    // Opcional: montar um .ovpn com os blocos embutidos
    let ovpn = make_ovpn("vpn.example.com:1194", &String::from_utf8(client_cert_pem)?, &String::from_utf8(client_key_pem)?, &ca_cert.to_pem()?.iter().map(|b| *b).collect::<Vec<u8>>())?;
    println!("--- SAMPLE .ovpn ---\n{}", ovpn);

    Ok(())
}

fn make_ovpn(remote: &str, client_cert_pem: &str, client_key_pem: &str, ca_pem_bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let ca_pem = String::from_utf8(ca_pem_bytes.to_vec())?;
    let ovpn = format!(
r#"client
dev tun
proto udp
remote {remote}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
verb 3

<ca>
{ca}
</ca>

<cert>
{cert}
</cert>

<key>
{key}
</key>
"#,
        remote = remote,
        ca = ca_pem.trim(),
        cert = client_cert_pem.trim(),
        key = client_key_pem.trim()
    );

    Ok(ovpn)
}
*/