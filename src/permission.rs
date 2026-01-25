//! Permission levels for type-safe access control.
//!
//! This module provides a generic interface for permission levels that can be
//! used to enforce compile-time permission checking. Applications use the
//! `Level` trait and standard level types to create typed permission tokens.
//!
//! # Example
//!
//! ```ignore
//! use runway::level::{View, Edit, Admin};
//! use runway::Level;
//!
//! // Permission<L> can only be obtained by passing a permission check
//! let perm: Permission<Edit> = permission::require::<Edit>(&conn, &user_id, &board).await?;
//!
//! // Operations require specific permission levels
//! board::update(&conn, &board, perm, req).await?;  // Compiler enforces Edit permission
//! ```

/// Marker trait for permission levels.
///
/// Implementors define an ordinal for runtime comparison.
/// Standard levels: View (1) < Edit (2) < Admin (3)
pub trait Level: Clone + Copy + PartialEq + Eq + PartialOrd + Ord + std::fmt::Debug {
    /// Ordinal value for runtime comparison.
    /// Higher ordinal = more permissive.
    const ORDINAL: u8;
}

/// Standard permission levels (View < Edit < Admin).
pub mod level {
    use super::Level;

    /// Read-only access level.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub struct View;

    impl Level for View {
        const ORDINAL: u8 = 1;
    }

    /// Content editing access level.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Edit;

    impl Level for Edit {
        const ORDINAL: u8 = 2;
    }

    /// Administrative access level.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Admin;

    impl Level for Admin {
        const ORDINAL: u8 = 3;
    }
}
