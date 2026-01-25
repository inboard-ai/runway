//! Permission trait for resource-level access control.
//!
//! This module provides a generic interface for permission levels that can be
//! compared, combined, and checked for capabilities. Applications implement
//! this trait for their domain-specific permission types.
//!
//! # Example
//!
//! ```ignore
//! use runway::Permission;
//!
//! #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
//! pub struct BoardPermission(u8);
//!
//! impl Permission for BoardPermission {
//!     fn none() -> Self { Self(0) }
//!     fn view() -> Self { Self(1) }
//!     fn edit() -> Self { Self(2) }
//!     fn admin() -> Self { Self(3) }
//!     fn owner() -> Self { Self(4) }
//!
//!     fn can_view(&self) -> bool { self.0 >= 1 }
//!     fn can_edit(&self) -> bool { self.0 >= 2 }
//!     fn can_admin(&self) -> bool { self.0 >= 3 }
//!     fn is_owner(&self) -> bool { self.0 >= 4 }
//! }
//! ```

/// A permission level that can be compared and combined.
///
/// Implementations should be ordered from least to most permissive:
/// `none < view < edit < admin < owner`
///
/// This ordering allows using `Ord` comparison and the `max` method
/// to combine permissions from multiple sources.
pub trait Permission: Clone + Copy + Eq + Ord + Sized {
    /// No permission (denied access).
    fn none() -> Self;

    /// Can view the resource (read-only access).
    fn view() -> Self;

    /// Can edit the resource content.
    fn edit() -> Self;

    /// Can administer the resource (manage settings, shares, members).
    fn admin() -> Self;

    /// Full ownership (can delete, transfer ownership).
    fn owner() -> Self;

    /// Check if this permission allows viewing.
    fn can_view(&self) -> bool;

    /// Check if this permission allows editing.
    fn can_edit(&self) -> bool;

    /// Check if this permission allows administration.
    fn can_admin(&self) -> bool;

    /// Check if this is owner-level permission.
    fn is_owner(&self) -> bool;

    /// Combine two permissions, taking the higher level.
    ///
    /// This is useful when a user has permissions from multiple sources
    /// (e.g., team membership + explicit share) and you want the effective
    /// permission to be the maximum of all grants.
    fn max(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }
}
