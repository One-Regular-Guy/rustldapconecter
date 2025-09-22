use std::sync::Arc;

use ldap3::{Ldap, ResultEntry, Scope, SearchEntry};
use openssl::{asn1::Asn1Time, bn::BigNum, hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, rsa::Rsa, x509::{extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName}, X509Builder, X509NameBuilder, X509}};
use tracing::info;


use crate::models::errors::AppError;

#[derive(Clone)]
pub struct LdapService {
    ldap: Ldap,
    base: Arc<String>,
    cert: Arc<X509>,
    key: Arc<PKey<Private>>
}

impl LdapService {
    pub fn new(ldap: Ldap, base: Arc<String>, cert: Arc<X509>, key: Arc<PKey<Private>>) -> Self {
        Self { ldap, base, cert, key }
    }
    pub async fn signin_execute(&self,incomming_email: impl Into<String>) -> Result<String, AppError> {
        let mut ldap_instance = self.ldap.clone();
        let incomming_email: String = incomming_email.into();

        let rsa = Rsa::generate(2048)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        let client_key = PKey::from_rsa(rsa)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;

        // Construir o subject do cliente
        let client_cn = &incomming_email;
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, &client_cn)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        let subject_name = name_builder.build();

        // Serial number aleatório
        let mut serial = BigNum::new()
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        serial
            .rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        let serial = serial
            .to_asn1_integer()
            .map_err(|e| AppError::ProviderError(e.to_string()))?;

        // Build do certificado
        let mut builder = X509Builder::new()
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        builder
            .set_version(2)
            .map_err(|e| AppError::ProviderError(e.to_string()))?; // X509 v3 (version value is v-1)
        builder
            .set_serial_number(&serial)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        builder
            .set_subject_name(&subject_name)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        let ca_cert = self.cert.clone();
        // issuer = CA subject
        builder
            .set_issuer_name(&*ca_cert.subject_name())
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        builder
            .set_not_before(
                Asn1Time::days_from_now(0)
                    .map_err(|e| AppError::ProviderError(e.to_string()))?
                    .as_ref()
            )
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        // validade por 1 ano (ajuste conforme necessário)
        builder
            .set_not_after(
                Asn1Time::days_from_now(365)
                    .map_err(|e| AppError::ProviderError(e.to_string()))?
                    .as_ref()
            )
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        builder
            .set_pubkey(&client_key)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;

        // Extensions: basicConstraints - not a CA
        let bc = BasicConstraints::new()
            .critical()
            .build()
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        builder
            .append_extension(bc)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;

        // keyUsage
        let ku = KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        builder
            .append_extension(ku)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;

        // extendedKeyUsage (clientAuth)
        let eku = ExtendedKeyUsage::new()
            .client_auth()
            .build()
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        builder
            .append_extension(eku)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;

        // opcional: SubjectAltName se quiser IPs/DNS (exemplo DNS)
        let san = SubjectAlternativeName::new()
            .dns(&client_cn)
            .build(
                &builder
                    .x509v3_context(Some(&ca_cert), None)
            )
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        builder
            .append_extension(san)
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        let ca_key = self.key.clone();
        // Assinar com a chave da CA (SHA256)
        builder.sign(&*ca_key, MessageDigest::sha256())
            .map_err(|e| AppError::ProviderError(e.to_string()))?;

        let client_cert: X509 = builder.build();

        // Serializar para PEM
        let client_cert_pem = client_cert
            .to_pem()
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        let client_key_pem = client_key
            .private_key_to_pem_pkcs8()
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        info!("Cert: {}", String::from_utf8(client_cert_pem).map_err(|e| AppError::ProviderError(e.to_string()))?);
        info!("Key: {}", String::from_utf8(client_key_pem).map_err(|e| AppError::ProviderError(e.to_string()))?);

        let my_filter = format!("(mail={})",incomming_email);
        let (mut rs, _re): (Vec<ResultEntry>, _) = ldap_instance.search(
            &*self.base.clone(),
            Scope::OneLevel,
            &my_filter,
            vec!["cn", "uid"]
        )
        .await
        .map_err(|e| AppError::ProviderError(e.to_string()))?
        .success()
        .map_err(|e| AppError::ProviderError(e.to_string()))?;
        match rs.pop() {
            Some(result) => {
                let search_entry = SearchEntry::construct(result);
                match search_entry.attrs.get("uid") {
                    Some(uid) => {
                        let mut poppable_uid = uid.to_owned(); 
                        match poppable_uid.pop() {
                            Some(response) => Ok(response),
                            None => Err(AppError::ProviderError("Lacking UID".to_string()))
                        }
                    },
                    None => Err(AppError::ProviderError("Lacking UID".to_string()))
                }
            }
            None => Err(AppError::ProviderError("Lacking Response".to_string()))
        }
        
    }
}