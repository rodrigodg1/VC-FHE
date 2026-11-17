use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tfhe::{prelude::*, FheUint64};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum SourceRef {
    Input { index: usize },
    Output { index: usize },
    Constant { value: String },
}

impl SourceRef {
    pub fn public_value(&self) -> Result<Option<u64>> {
        match self { Self::Constant { value } => Ok(Some(value.parse()?)), _ => Ok(None) }
    }
    pub fn name(&self) -> &'static str {
        match self { Self::Input { .. } => "AUTHENTICATED_INPUT",
            Self::Output { .. } => "PREVIOUS_OUTPUT", Self::Constant { .. } => "PUBLIC_CONSTANT" }
    }
    pub fn resolve(&self, outputs: &[FheUint64], input: impl FnOnce(usize) -> Result<FheUint64>) -> Result<FheUint64> {
        match self {
            Self::Input { index } => input(*index),
            Self::Output { index } => match outputs.get(*index) {
                Some(value) => Ok(value.clone()), None => bail!("forward or missing output {index}")
            },
            Self::Constant { value } => Ok(FheUint64::encrypt_trivial(value.parse::<u64>()?)),
        }
    }
}
