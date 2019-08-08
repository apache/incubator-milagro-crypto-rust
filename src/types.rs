#[derive(PartialEq)]
pub enum ModType {
    NotSpecial,
    PseudoMersenne,
    MontgomeryFriendly,
    GeneralisedMersenne,
}

#[derive(PartialEq)]
pub enum CurveType {
    Edwards,
    Weierstrass,
    Montgomery,
}

#[derive(PartialEq)]
pub enum CurvePairingType {
    Not,
    Bn,
    Bls,
}

#[derive(PartialEq)]
pub enum SexticTwist {
    Not,
    DType,
    MType,
}
impl Into<usize> for SexticTwist {
    fn into(self) -> usize {
        match self {
            SexticTwist::Not => 0,
            SexticTwist::DType => 0,
            SexticTwist::MType => 1,
        }
    }
}

#[derive(PartialEq)]
pub enum SignOfX {
    Not,
    PositiveX,
    NegativeX,
}
