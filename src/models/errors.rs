use std::fmt;

#[derive(Debug)]
pub enum AppError {
    ValidationError(String),
    DatabaseError(String),
    CacheError(String),
    ProviderError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AppError::ValidationError(origin) => write!(f, "Invalid Field: {}", origin),
            AppError::ProviderError(origin) => write!(f, "Error when providing: {}", origin),
            AppError::DatabaseError(origin) => write!(f, "Database Error: {}",origin),
            AppError::CacheError(origin) => write!(f, "Cache Error: {}", origin)
        }        
    }
}
