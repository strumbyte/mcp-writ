//! Owner-only temporary directories for policy and build staging, plus
//! copy primitives that cannot be raced out of a staged source tree:
//! every copied file is opened without following a final-component link
//! and proven to resolve inside the canonicalized source root, and the
//! bytes stream from that same open handle — a pathname swapped for a
//! link mid-copy can never redirect the read to an out-of-tree target.

mod copy;
mod file_io;
mod handle;
mod pinned;
mod tempdir;
#[cfg(windows)]
mod winsec;

pub use copy::{
    CopyBudget, SafeCopyOutcome, canonical_root, safe_copy_dir, safe_copy_file,
    safe_copy_file_bounded, should_skip_build_entry,
};
pub use file_io::{
    read_file_bounded, read_no_follow_bounded, read_no_follow_bounded_in, read_text_bounded,
    read_text_bounded_follow_links, read_text_bounded_follow_links_resolved, write_file_atomic,
};
pub use pinned::{
    FileIdentity, PinnedDir, dir_shared_writable, file_identity, open_dir_pinned,
    require_parent_write_restricted, running_as_root,
};
#[cfg(windows)]
pub use tempdir::restrict_handle_owner_only;
pub use tempdir::{create_private_tempdir, restrict_owner_only};
#[cfg(windows)]
pub(crate) use winsec::{
    dacl_grants_file_write, dir_dacl_grants_replace_rights, handle_dacl_grants_file_write,
    handle_owner_is_trusted, opened_at_literal_path, path_owner_is_trusted,
    require_no_reparse_ancestors,
};

#[cfg(test)]
mod tests;
