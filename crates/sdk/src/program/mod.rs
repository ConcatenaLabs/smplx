/// Definitions and traits for handling program arguments in Simplicity programs.
pub mod arguments;
/// The execution budget of a Simplicity spend, and the annex that raises it.
pub mod budget;
/// Core definitions, features, and abstractions for working with Simplicity programs.
pub mod core;
/// Error types and definitions for program compilation, manipulation, and execution failures.
pub mod error;
/// Program execution's specific logger
pub mod logger;
/// Definitions and traits for resolving and satisfying execution witnesses for Simplicity programs.
pub mod witness;

pub use arguments::ArgumentsTrait;
pub use budget::{ANNEX_TAG, BudgetError, BudgetRule, SpendBudget};
pub use core::{FinalizedSpend, Program, ProgramTrait};
pub use error::ProgramError;
pub use simplicityhl::tracker::TrackerLogLevel;
pub use witness::WitnessTrait;
