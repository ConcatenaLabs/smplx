//! The execution budget of a Simplicity spend, and the annex that raises it.
//!
//! A Simplicity program carries a static bound on its cost, and consensus runs it only when that
//! bound fits the budget its input's witness earns: so many weight units per byte of the input's
//! serialized witness stack, plus 50, capped at 4,000,050. A program that costs more than its
//! witness earns is padded with an annex, the last witness item, tagged `0x50`: its bytes add to
//! the stack and so to the budget, and the program never reads them. A full signature hash commits
//! to every input's annex, so the padding is fixed before anything is signed.

use simplicityhl::simplicity::Cost;

/// The first byte of a taproot annex (BIP 341).
pub const ANNEX_TAG: u8 = 0x50;

/// Errors raised when a program costs more than its spend can be given.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    /// The program costs more than any spend can be given.
    #[error("The program costs {cost_milliweight} milli-WU, above the {max} WU any spend can be given")]
    AboveConsensusMax {
        /// The program's cost bound, in milli weight units.
        cost_milliweight: u64,
        /// The largest budget consensus grants, in weight units.
        max: u64,
    },

    /// The annex the program needs is larger than this network relays.
    #[error(
        "The program costs {cost_milliweight} milli-WU and its witness earns {budget} WU; it needs a \
         {needed}-byte annex, and this network relays at most {limit} bytes"
    )]
    AnnexBeyondLimit {
        /// The program's cost bound, in milli weight units.
        cost_milliweight: u64,
        /// What the unpadded witness earns, in weight units.
        budget: u64,
        /// The annex the program needs, tag byte included.
        needed: usize,
        /// The largest annex this network relays.
        limit: usize,
    },
}

/// How a network turns a Simplicity spend's witness into execution budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetRule {
    /// Weight units of budget each byte of the serialized witness stack earns.
    pub per_witness_byte: u64,
    /// The largest annex, tag byte included, that this network relays on a Simplicity spend:
    /// zero where it relays none.
    pub max_standard_annex: usize,
}

/// What a Simplicity spend costs and what its witness earns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendBudget {
    /// The program's cost bound, in milli weight units.
    pub cost_milliweight: u64,
    /// The budget the witness earns, in weight units, its annex included.
    pub budget: u64,
    /// The serialized size of the witness stack, its annex included.
    pub witness_bytes: usize,
    /// The annex's size, tag byte included; zero when the spend carries none.
    pub annex_bytes: usize,
}

impl BudgetRule {
    /// Elements' rule: one weight unit per witness byte, and no annex relays.
    pub const ELEMENTS: Self = Self {
        per_witness_byte: 1,
        max_standard_annex: 0,
    };

    /// The budget every spend gets on top of what its witness earns.
    pub const OFFSET: u64 = 50;

    /// The largest budget consensus grants a spend, in weight units.
    pub const MAX: u64 = 4_000_050;

    /// The budget, in weight units, that a witness stack earns.
    #[must_use]
    pub fn budget(&self, stack: &[Vec<u8>]) -> u64 {
        Self::budget_of_size(self.per_witness_byte, serialized_size(stack))
    }

    /// Whether a program of this cost runs under the budget this witness stack earns.
    #[must_use]
    pub fn covers(&self, cost: Cost, stack: &[Vec<u8>]) -> bool {
        cost_milliweight(cost) <= self.budget(stack) * 1000
    }

    /// What a spend with this cost and witness stack costs and earns.
    #[must_use]
    pub fn report(&self, cost: Cost, stack: &[Vec<u8>]) -> SpendBudget {
        let annex_bytes = stack
            .last()
            .filter(|item| stack.len() >= 2 && item.first() == Some(&ANNEX_TAG))
            .map_or(0, Vec::len);

        SpendBudget {
            cost_milliweight: cost_milliweight(cost),
            budget: self.budget(stack),
            witness_bytes: serialized_size(stack),
            annex_bytes,
        }
    }

    /// The smallest annex that lets a program of this cost run when appended to `stack`, which
    /// must not carry one already; `None` when the stack earns enough without one.
    ///
    /// # Errors
    /// Returns a `BudgetError` when no spend can be given that much, or when the annex needed is
    /// larger than this network relays.
    pub fn padding(&self, cost: Cost, stack: &[Vec<u8>]) -> Result<Option<Vec<u8>>, BudgetError> {
        let cost_milliweight = cost_milliweight(cost);

        if cost_milliweight > Self::MAX * 1000 {
            return Err(BudgetError::AboveConsensusMax {
                cost_milliweight,
                max: Self::MAX,
            });
        }

        let budget = self.budget(stack);

        if cost_milliweight <= budget * 1000 {
            return Ok(None);
        }

        // The serialized stack must reach this many bytes.
        let target = cost_milliweight.div_ceil(1000).saturating_sub(Self::OFFSET);
        let needed_bytes = usize::try_from(target.div_ceil(self.per_witness_byte)).unwrap_or(usize::MAX);

        // The annex adds its bytes and its length prefix, and may lengthen the item count.
        let without = serialized_size(stack) - compact_size_len(stack.len());
        let fixed = without + compact_size_len(stack.len() + 1);
        let size_with = |len: usize| fixed + compact_size_len(len) + len;

        let mut len = needed_bytes.saturating_sub(fixed + 9).max(1);
        while size_with(len) < needed_bytes {
            len += 1;
        }

        if len > self.max_standard_annex {
            return Err(BudgetError::AnnexBeyondLimit {
                cost_milliweight,
                budget,
                needed: len,
                limit: self.max_standard_annex,
            });
        }

        let mut annex = vec![0; len];
        annex[0] = ANNEX_TAG;

        Ok(Some(annex))
    }

    fn budget_of_size(per_witness_byte: u64, size: usize) -> u64 {
        let size = u64::try_from(size).unwrap_or(u64::MAX);

        size.saturating_mul(per_witness_byte)
            .saturating_add(Self::OFFSET)
            .min(Self::MAX)
    }
}

/// A cost bound in milli weight units.
///
/// # Panics
/// Never: a cost prints as its milli weight units.
#[must_use]
pub fn cost_milliweight(cost: Cost) -> u64 {
    cost.to_string()
        .parse()
        .expect("a cost prints as its milli weight units")
}

/// The size of a witness stack as consensus serializes it: the item count, then each item's
/// length and bytes.
#[must_use]
pub fn serialized_size(stack: &[Vec<u8>]) -> usize {
    compact_size_len(stack.len())
        + stack
            .iter()
            .map(|item| compact_size_len(item.len()) + item.len())
            .sum::<usize>()
}

fn compact_size_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOUR_PER_BYTE: BudgetRule = BudgetRule {
        per_witness_byte: 4,
        max_standard_annex: 100_000,
    };

    fn stack(sizes: &[usize]) -> Vec<Vec<u8>> {
        sizes.iter().map(|&n| vec![0xab; n]).collect()
    }

    fn cost(wu: u64) -> Cost {
        Cost::from_milliweight(u32::try_from(wu * 1000).unwrap())
    }

    #[test]
    fn serialized_size_counts_the_prefixes() {
        assert_eq!(serialized_size(&[]), 1);
        assert_eq!(serialized_size(&stack(&[64, 200, 32, 65])), 1 + 65 + 201 + 33 + 66);
        assert_eq!(serialized_size(&stack(&[300])), 1 + 3 + 300);
    }

    #[test]
    fn budget_is_bytes_times_rate_plus_fifty_capped() {
        let witness = stack(&[64, 200, 32, 65]);

        assert_eq!(BudgetRule::ELEMENTS.budget(&witness), 366 + 50);
        assert_eq!(FOUR_PER_BYTE.budget(&witness), 4 * 366 + 50);
        assert_eq!(FOUR_PER_BYTE.budget(&stack(&[2_000_000])), BudgetRule::MAX);
    }

    #[test]
    fn no_padding_when_the_witness_earns_enough() {
        let witness = stack(&[64, 200, 32, 65]);
        let budget = FOUR_PER_BYTE.budget(&witness);

        assert_eq!(FOUR_PER_BYTE.padding(cost(budget), &witness), Ok(None));
        assert!(FOUR_PER_BYTE.covers(cost(budget), &witness));
        assert!(!FOUR_PER_BYTE.covers(
            Cost::from_milliweight(u32::try_from(budget * 1000 + 1).unwrap()),
            &witness
        ));
    }

    // The annex is the smallest that covers the cost: one byte less does not.
    #[test]
    fn padding_is_the_smallest_annex_that_covers_the_cost() {
        let witness = stack(&[64, 200, 32, 65]);

        for wu in [1_515, 1_600, 2_000, 2_534, 10_000, 100_000, 300_000] {
            let annex = FOUR_PER_BYTE.padding(cost(wu), &witness).unwrap().unwrap();
            assert_eq!(annex[0], ANNEX_TAG);
            assert!(annex[1..].iter().all(|&b| b == 0));

            let mut padded = witness.clone();
            padded.push(annex.clone());
            assert!(FOUR_PER_BYTE.covers(cost(wu), &padded), "{wu} WU");

            if annex.len() > 1 {
                let mut short = witness.clone();
                short.push(annex[..annex.len() - 1].to_vec());
                assert!(!FOUR_PER_BYTE.covers(cost(wu), &short), "{wu} WU");
            }
        }
    }

    #[test]
    fn padding_crosses_the_three_byte_length_prefix() {
        let witness = stack(&[64, 200, 32, 65]);
        let mut seen = Vec::new();

        for wu in 2_400..2_600 {
            let annex = FOUR_PER_BYTE.padding(cost(wu), &witness).unwrap().unwrap();
            let mut padded = witness.clone();
            padded.push(annex.clone());

            assert!(FOUR_PER_BYTE.covers(cost(wu), &padded));
            seen.push(annex.len());
        }

        assert!(seen.iter().any(|&n| n < 0xfd) && seen.iter().any(|&n| n >= 0xfd));
    }

    #[test]
    fn beyond_the_relay_limit_or_the_cap_is_refused() {
        let witness = stack(&[64, 200, 32, 65]);

        assert!(matches!(
            FOUR_PER_BYTE.padding(cost(500_000), &witness),
            Err(BudgetError::AnnexBeyondLimit { limit: 100_000, .. })
        ));
        assert!(matches!(
            BudgetRule::ELEMENTS.padding(cost(1_000), &witness),
            Err(BudgetError::AnnexBeyondLimit {
                limit: 0,
                needed: 581,
                ..
            })
        ));
        assert!(matches!(
            FOUR_PER_BYTE.padding(cost(4_000_051), &witness),
            Err(BudgetError::AboveConsensusMax { .. })
        ));
    }

    #[test]
    fn the_largest_relayed_annex_covers_its_whole_budget() {
        let witness = stack(&[64, 200, 32, 65]);
        let mut padded = witness.clone();
        padded.push(vec![0; 100_000]);
        let most = FOUR_PER_BYTE.budget(&padded);

        let annex = FOUR_PER_BYTE.padding(cost(most), &witness).unwrap().unwrap();
        assert_eq!(annex.len(), 100_000);
        assert!(FOUR_PER_BYTE.padding(cost(most + 1), &witness).is_err());
    }

    #[test]
    fn report_reads_the_annex_back() {
        let mut witness = stack(&[64, 200, 32, 65]);
        let plain = FOUR_PER_BYTE.report(cost(100), &witness);
        assert_eq!(plain.annex_bytes, 0);
        assert_eq!(plain.cost_milliweight, 100_000);

        witness.push(vec![ANNEX_TAG, 0, 0]);
        let padded = FOUR_PER_BYTE.report(cost(100), &witness);
        assert_eq!(padded.annex_bytes, 3);
        assert_eq!(padded.witness_bytes, plain.witness_bytes + 4);
        assert_eq!(padded.budget, plain.budget + 16);
    }
}
