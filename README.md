# rustldapconecter

```rust
use ldap3::{LdapConn, Scope, SearchEntry, ResultEntry};
use ldap3::result::Result;

fn search_account(ldap_conn: &mut LdapConn) -> Result<()> {
    let (rs, _re): (Vec<ResultEntry>, _) = ldap_conn.search(
        "ou=accounts,dc=domain,dc=com",
        Scope::OneLevel,
        "(mail=teste@mail.com)",
        vec!["cn", "uid"]
    )?.success()?;
    
    for entry in rs {
        let search_entry = SearchEntry::construct(entry);
        println!("{:?}", search_entry);
    }
    
    Ok(())
}

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:389")?;
    search_account(&mut ldap)?;
    ldap.unbind()?;
    Ok(())
}
```