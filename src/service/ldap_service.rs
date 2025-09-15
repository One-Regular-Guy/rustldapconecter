use std::sync::Arc;

use ldap3::{Ldap, ResultEntry, Scope, SearchEntry};


use crate::models::errors::AppError;

#[derive(Clone)]
pub struct LdapService {
    ldap: Ldap,
    base: Arc<String>
}

impl LdapService {
    pub fn new(ldap: Ldap, base: Arc<String>) -> Self {
        Self { ldap, base }
    }
    pub async fn signin_execute(&self,incomming_email: impl Into<String>) -> Result<String, AppError> {
        let mut ldap_instance = self.ldap.clone();
        let incomming_email = incomming_email.into();
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