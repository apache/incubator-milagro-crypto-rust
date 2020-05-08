#[derive(Debug, PartialEq, Clone)]
pub enum AmclError {
    AggregateEmptyPoints,
    HashToFieldError,
    InvalidSecretKeySize,
    InvalidSecretKeyRange,
}
