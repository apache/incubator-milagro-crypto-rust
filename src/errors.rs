#[derive(Debug, PartialEq, Clone)]
pub enum AmclError {
    AggregateEmptyPoints,
    HashToFieldError,
    InvalidSecretKeySize,
    InvalidSecretKeyRange,
    InvalidPoint,
    InvalidG1Size,
    InvalidG2Size,
    InvalidYFlag,
}
