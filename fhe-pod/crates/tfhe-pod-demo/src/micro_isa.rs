//! The checked value relation shared by the local executor and adjudicator.
//! See docs/ARCHITECTURE.md and the independent Solidity/JS relations.
use anyhow::{Result, anyhow, bail};
use tfhe::prelude::*;
use tfhe::{FheBool, FheUint8, FheUint64};

pub struct CheckedEvaluation {
    pub value: FheUint64,
    pub valid: FheBool,
}

impl CheckedEvaluation {
    /// The only predicate eligible for a value-leaf decision. Authorization
    /// to open it must be established separately, before decryption.
    pub fn accepts(&self, claimed: &FheUint64) -> FheBool {
        &self.valid & self.value.eq(claimed)
    }
}

pub fn rhs_is_public_scalar(opcode: &str) -> bool {
    matches!(opcode, "DIV" | "MOD" | "SHR" | "ADD_CHAIN")
}

pub fn evaluate(
    opcode: &str,
    lhs: &FheUint64,
    rhs_ciphertext: Option<&FheUint64>,
    scalar: u64,
) -> Result<CheckedEvaluation> {
    let rhs = || rhs_ciphertext.ok_or_else(|| anyhow!("{opcode} requires encrypted rhs"));
    let yes = || FheBool::encrypt_trivial(true);
    let invalid = || CheckedEvaluation {
        value: FheUint64::encrypt_trivial(0u64),
        valid: FheBool::encrypt_trivial(false),
    };
    let (value, valid) = match opcode {
        "ADD" => {
            let value = lhs + rhs()?;
            let valid = value.ge(lhs);
            (value, valid)
        }
        "SUB" => (lhs - rhs()?, lhs.ge(rhs()?)),
        "MUL" => {
            let (value, overflow) = lhs.overflowing_mul(rhs()?);
            (value, !overflow)
        }
        "DIV" | "MOD" if scalar == 0 => return Ok(invalid()),
        "DIV" => (lhs / scalar, yes()),
        "MOD" => (lhs % scalar, yes()),
        "SHR" if scalar >= 64 => return Ok(invalid()),
        "SHR" => (lhs >> scalar, yes()),
        "ADD_CHAIN" if !(1..=8).contains(&scalar) => return Ok(invalid()),
        "ADD_CHAIN" => {
            let mut value = lhs.clone();
            for _ in 0..scalar {
                value = &value + 1u64;
            }
            let valid = value.ge(lhs);
            (value, valid)
        }
        "CAST_U8" => (
            FheUint64::cast_from(FheUint8::cast_from(lhs.clone())),
            yes(),
        ),
        "MIN" => (lhs.min(rhs()?), yes()),
        "EQ" => (FheUint64::cast_from(lhs.eq(rhs()?)), yes()),
        "LT" => (FheUint64::cast_from(lhs.lt(rhs()?)), yes()),
        "GT" => (FheUint64::cast_from(lhs.gt(rhs()?)), yes()),
        "BITAND" => (lhs & rhs()?, yes()),
        "BITOR" => (lhs | rhs()?, yes()),
        "BITXOR" => (lhs ^ rhs()?, yes()),
        _ => bail!("unsupported adjudicated opcode {opcode}"),
    };
    Ok(CheckedEvaluation { value, valid })
}
