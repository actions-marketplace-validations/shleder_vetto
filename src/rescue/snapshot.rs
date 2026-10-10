//! Project Snapshot & Rollback Engine (Feature 32).
//!
//! Creates a TAR archive of project files before session execution in `~/.vetto/snapshots/<session>/`
//! with a strict size limit, and provides rollback functionality to restore files.

use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Maximum size permitted for a single project snapshot (50 MB).
pub const DEFAULT_MAX_SNAPSHOT_SIZE: u64 = 50 * 1024 * 1024;

/// Metadata stored alongside the snapshot archive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SnapshotMetadata {
    pub session_id: String,
    pub created_at: String,
    pub project_dir: PathBuf,
    pub archive_file: PathBuf,
    pub file_count: usize,
    pub total_size_bytes: u64,
}

pub use super::rollback::{
    rollback_session, rollback_session as rollback_snapshot, RollbackResult,
};

/// Resolves the snapshots root directory (`~/.vetto/snapshots`).
pub fn snapshots_root_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither HOME nor USERPROFILE is set")?;
    Ok(home.join(".vetto").join("snapshots"))
}

/// Lists all available project snapshots across all sessions, ordered newest first.
pub fn list_snapshots() -> Result<Vec<SnapshotMetadata>> {
    let root = match snapshots_root_dir() {
        Ok(dir) => dir,
        Err(_) => return Ok(Vec::new()),
    };
    list_snapshots_in(&root)
}

/// Same as [`list_snapshots`], but rooted at an explicit directory.
/// Production passes the real store root; tests pass a fresh temp dir so
/// they stay hermetic against the shared per-user store ($HOME/.vetto).
pub fn list_snapshots_in(root: &Path) -> Result<Vec<SnapshotMetadata>> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    // Transient IO failures (Windows Defender locks on fresh dirs, loaded
    // CI runners) must not masquerade as "no snapshots": retry briefly,
    // then fail loudly instead of returning a lying empty list.
    let mut last_err = String::new();
    for _ in 0..3 {
        match std::fs::read_dir(root) {
            Ok(entries) => {
                let mut snapshots = Vec::new();
                for entry in entries.flatten() {
                    let meta_file = entry.path().join("metadata.json");
                    if meta_file.is_file() {
                        if let Ok(text) = std::fs::read_to_string(&meta_file) {
                            if let Ok(meta) = serde_json::from_str::<SnapshotMetadata>(&text) {
                                snapshots.push(meta);
                            }
                        }
                    }
                }

                snapshots.sort_by(|a, b| {
                    b.created_at
                        .cmp(&a.created_at)
                        .then_with(|| b.session_id.cmp(&a.session_id))
                });
                return Ok(snapshots);
            }
            Err(e) => {
                last_err = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    bail!("cannot list snapshots in {}: {last_err}", root.display())
}

/// Inspect entries in a snapshot archive, returning relative paths and byte sizes.
pub fn inspect_snapshot_archive(session: &str) -> Result<Vec<(String, u64)>> {
    let session_path = Path::new(session);
    let archive_path = if session_path.is_file() {
        session_path.to_path_buf()
    } else {
        let root = snapshots_root_dir()?;
        let dir = root.join(session);
        if !dir.exists() {
            bail!(
                "snapshot for session '{session}' was not found in {}",
                root.display()
            );
        }
        let archive = dir.join("snapshot.tar");
        if !archive.exists() {
            bail!("snapshot archive '{}' not found", archive.display());
        }
        archive
    };

    let mut archive_file = File::open(&archive_path)
        .with_context(|| format!("failed to open snapshot archive {}", archive_path.display()))?;

    let mut entries = Vec::new();
    loop {
        let mut header = [0u8; 512];
        let n = archive_file.read(&mut header)?;
        if n < 512 || header.iter().all(|&b| b == 0) {
            break;
        }

        let (name, size) = parse_tar_header(&header)?;
        if name.is_empty() {
            break;
        }

        let clean_path = Path::new(&name);
        if !clean_path.is_absolute()
            && !clean_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            entries.push((name, size));
        }

        let padding = (512 - (size % 512)) % 512;
        let to_skip = size + padding;
        archive_file.seek(std::io::SeekFrom::Current(to_skip as i64))?;
    }

    Ok(entries)
}

/// Create a project snapshot for the given session.
pub fn create_snapshot(
    project_dir: &Path,
    session_id: &str,
    max_bytes: u64,
) -> Result<SnapshotMetadata> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from));
    let is_home_or_root = project_dir.parent().is_none()
        || std::fs::canonicalize(project_dir)
            .map(|cp| cp.parent().is_none())
            .unwrap_or(false)
        || home
            .as_deref()
            .map(|h| {
                h == project_dir
                    || match (std::fs::canonicalize(h), std::fs::canonicalize(project_dir)) {
                        (Ok(ch), Ok(cp)) => ch == cp,
                        _ => false,
                    }
            })
            .unwrap_or(false);
    if is_home_or_root {
        tracing::debug!(
            "vetto: snapshot skipped for user home or root filesystem: {}",
            project_dir.display()
        );
        let archive_file = snapshots_root_dir()
            .unwrap_or_else(|_| std::env::temp_dir().join(".vetto").join("snapshots"))
            .join(session_id)
            .join("snapshot.tar");
        return Ok(SnapshotMetadata {
            session_id: session_id.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            project_dir: project_dir.to_path_buf(),
            archive_file,
            file_count: 0,
            total_size_bytes: 0,
        });
    }

    let snapshots_dir = snapshots_root_dir()?.join(session_id);
    std::fs::create_dir_all(&snapshots_dir)
        .with_context(|| format!("create snapshot dir {}", snapshots_dir.display()))?;

    let archive_path = snapshots_dir.join("snapshot.tar");
    let file = File::create(&archive_path)
        .with_context(|| format!("create archive {}", archive_path.display()))?;
    let mut file = std::io::BufWriter::new(file);

    let mut file_count = 0;
    let mut total_size = 0u64;

    let mut queue = vec![project_dir.to_path_buf()];
    while let Some(dir) = queue.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                if !crate::fs::is_ignored_directory(&name) {
                    queue.push(path);
                }
            } else if file_type.is_file() {
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                let file_len = meta.len();
                if total_size + file_len > max_bytes {
                    // Clean up and fail closed
                    drop(file);
                    let _ = std::fs::remove_file(&archive_path);
                    let _ = std::fs::remove_dir_all(&snapshots_dir);
                    eprintln!(
                        "vetto: warning: project size exceeds snapshot limit ({} MB); snapshot aborted (undo/rollback disabled).",
                        max_bytes / (1024 * 1024)
                    );
                    bail!(
                        "project size (exceeds {} MB) exceeds maximum snapshot limit; snapshot aborted",
                        max_bytes / (1024 * 1024)
                    );
                }

                if let Ok(rel) = path.strip_prefix(project_dir) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    let mut data = Vec::with_capacity(file_len as usize);
                    let Ok(mut f) = File::open(&path) else {
                        continue;
                    };
                    if f.read_to_end(&mut data).is_ok() {
                        #[cfg(unix)]
                        let mode = {
                            use std::os::unix::fs::PermissionsExt;
                            meta.permissions().mode() & 0o777
                        };
                        #[cfg(not(unix))]
                        let mode = 0o644;

                        write_tar_entry_with_mode(
                            &mut file,
                            &rel_str,
                            &data,
                            meta.modified().unwrap_or(SystemTime::now()),
                            mode,
                        )?;
                        file_count += 1;
                        total_size += file_len;
                    }
                }
            }
        }
    }

    // Write two 512-byte zero blocks to terminate TAR
    file.write_all(&[0u8; 1024])?;
    file.flush()?;

    let metadata = SnapshotMetadata {
        session_id: session_id.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        project_dir: project_dir.to_path_buf(),
        archive_file: archive_path,
        file_count,
        total_size_bytes: total_size,
    };

    let meta_path = snapshots_dir.join("metadata.json");
    let json_text = serde_json::to_string_pretty(&metadata)?;
    // Atomic publish: concurrent list_snapshots_in must never observe a
    // half-written metadata.json (TOCTOU omission). Tmp + rename is atomic.
    let tmp_path = snapshots_dir.join(format!("metadata.json.tmp.{}", std::process::id()));
    std::fs::write(&tmp_path, json_text)?;
    std::fs::rename(&tmp_path, &meta_path)?;

    Ok(metadata)
}

/// Attempts a Copy-on-Write reflink clone of `src` to `dst`, falling back to standard copy if unsupported.
pub fn try_reflink_clone(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let src_file = File::open(src)?;
        let dst_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dst)?;
        let ret = unsafe { libc::ioctl(dst_file.as_raw_fd(), 0x40049409, src_file.as_raw_fd()) };
        if ret == 0 {
            return Ok(());
        }
        drop(dst_file);
        drop(src_file);
        std::fs::copy(src, dst).map(|_| ())
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let src_c = CString::new(src.as_os_str().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let dst_c = CString::new(dst.as_os_str().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        extern "C" {
            fn clonefile(
                src: *const libc::c_char,
                dst: *const libc::c_char,
                flags: libc::c_int,
            ) -> libc::c_int;
        }
        let ret = unsafe { clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
        if ret == 0 {
            return Ok(());
        }
        std::fs::copy(src, dst).map(|_| ())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        std::fs::copy(src, dst).map(|_| ())
    }
}

pub fn write_tar_entry<W: Write>(
    writer: &mut W,
    path: &str,
    data: &[u8],
    mtime: SystemTime,
) -> Result<()> {
    write_tar_entry_with_mode(writer, path, data, mtime, 0o644)
}

pub fn write_tar_entry_with_mode<W: Write>(
    writer: &mut W,
    path: &str,
    data: &[u8],
    mtime: SystemTime,
    mode: u32,
) -> Result<()> {
    let mut header = [0u8; 512];

    // Name (100 bytes) and optional ustar prefix (155 bytes, bytes 345..500)
    let path_bytes = path.as_bytes();
    if path_bytes.len() <= 100 {
        header[..path_bytes.len()].copy_from_slice(path_bytes);
    } else {
        let mut split = None;
        let max_split = path_bytes.len().min(156);
        for i in (1..max_split).rev() {
            if path_bytes[i] == b'/' {
                let name_len = path_bytes.len() - i - 1;
                if name_len <= 100 && i <= 155 {
                    split = Some(i);
                    break;
                }
            }
        }
        if let Some(i) = split {
            let prefix = &path_bytes[..i];
            let name = &path_bytes[i + 1..];
            header[345..345 + prefix.len()].copy_from_slice(prefix);
            header[..name.len()].copy_from_slice(name);
        } else {
            anyhow::bail!(
                "path '{}' ({} bytes) cannot be split to fit ustar format limits (prefix <= 155, name <= 100)",
                path,
                path_bytes.len()
            );
        }
    }

    // Mode (8 bytes): octal mode
    let mode_oct = format!("{:07o}\0", mode & 0o777);
    header[100..108].copy_from_slice(mode_oct.as_bytes());
    // UID / GID: 0000000\0
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");

    // Size (12 bytes octal)
    let size_oct = format!("{:011o}\0", data.len());
    header[124..136].copy_from_slice(size_oct.as_bytes());

    // Mtime (12 bytes octal)
    let mtime_secs = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mtime_oct = format!("{:011o}\0", mtime_secs);
    header[136..148].copy_from_slice(mtime_oct.as_bytes());

    // Typeflag: '0' (regular file)
    header[156] = b'0';

    // Magic & version: "ustar\0" "00"
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    // Checksum placeholder (8 spaces)
    header[148..156].copy_from_slice(b"        ");
    let chksum: u32 = header.iter().map(|&b| b as u32).sum();
    let chksum_oct = format!("{:06o}\0 ", chksum);
    header[148..156].copy_from_slice(chksum_oct.as_bytes());

    writer.write_all(&header)?;
    writer.write_all(data)?;

    let padding = (512 - (data.len() % 512)) % 512;
    if padding > 0 {
        writer.write_all(&vec![0u8; padding])?;
    }

    Ok(())
}

pub fn parse_tar_header(header: &[u8; 512]) -> Result<(String, u64)> {
    let (name, size, _) = parse_tar_header_with_mode(header)?;
    Ok((name, size))
}

pub fn parse_tar_header_with_mode(header: &[u8; 512]) -> Result<(String, u64, u32)> {
    let name_bytes: Vec<u8> = header[..100]
        .iter()
        .take_while(|&&b| b != 0)
        .copied()
        .collect();
    let name = String::from_utf8_lossy(&name_bytes).to_string();

    let prefix_bytes: Vec<u8> = header[345..500]
        .iter()
        .take_while(|&&b| b != 0)
        .copied()
        .collect();
    let prefix = String::from_utf8_lossy(&prefix_bytes).to_string();
    let full_name = if !prefix.is_empty() {
        format!("{}/{}", prefix, name)
    } else {
        name
    };

    let mode_str = String::from_utf8_lossy(&header[100..108])
        .trim()
        .trim_matches('\0')
        .to_string();
    let mode = u32::from_str_radix(&mode_str, 8).unwrap_or(0o644);

    let size_str = String::from_utf8_lossy(&header[124..136])
        .trim()
        .trim_matches('\0')
        .to_string();
    let size = u64::from_str_radix(&size_str, 8).unwrap_or(0);

    Ok((full_name, size, mode))
}

/// Read entries, contents, and POSIX modes from a snapshot tar archive.
pub fn read_tar_archive_with_modes(path: &Path) -> Result<BTreeMap<String, (Vec<u8>, u32)>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open snapshot archive {}", path.display()))?;
    read_tar_entries_with_modes(file)
}

/// Read tar entries and POSIX modes from an arbitrary byte reader.
pub fn read_tar_entries_with_modes<R: Read>(
    mut reader: R,
) -> Result<BTreeMap<String, (Vec<u8>, u32)>> {
    let mut entries = BTreeMap::new();
    loop {
        let mut header = [0u8; 512];
        let n = reader.read(&mut header)?;
        if n < 512 || header.iter().all(|&b| b == 0) {
            break;
        }

        let (name, size, mode) = parse_tar_header_with_mode(&header)?;
        if name.is_empty() {
            break;
        }

        let mut data = vec![0u8; size as usize];
        reader.read_exact(&mut data)?;

        let padding = (512 - (size % 512)) % 512;
        if padding > 0 {
            let mut pad_buf = vec![0u8; padding as usize];
            reader.read_exact(&mut pad_buf)?;
        }

        let clean_path = Path::new(&name);
        if !clean_path.is_absolute()
            && !clean_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            let normalized = name.replace('\\', "/");
            entries.insert(normalized, (data, mode));
        }
    }
    Ok(entries)
}

/// Read entries and contents from a snapshot tar archive.
pub fn read_tar_archive(path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open snapshot archive {}", path.display()))?;
    read_tar_entries(file)
}

/// Read tar entries from an arbitrary byte reader.
pub fn read_tar_entries<R: Read>(reader: R) -> Result<BTreeMap<String, Vec<u8>>> {
    let entries = read_tar_entries_with_modes(reader)?;
    Ok(entries.into_iter().map(|(k, (v, _))| (k, v)).collect())
}

/// Scan current project directory, ignoring transient / toolchain folders.
pub fn scan_disk_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut queue = vec![root.to_path_buf()];

    while let Some(dir) = queue.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                if !crate::fs::is_ignored_directory(&name) {
                    queue.push(path);
                }
            } else if file_type.is_file() {
                if let Ok(rel) = path.strip_prefix(root) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    if let Ok(bytes) = std::fs::read(&path) {
                        files.insert(rel_str, bytes);
                    }
                }
            }
        }
    }

    Ok(files)
}

/// Returns a tuple `(modified_count, added_count, deleted_count)` comparing snapshot archive against disk.
pub fn preview_snapshot_changes(
    archive_path: &Path,
    project_dir: &Path,
) -> Result<(usize, usize, usize)> {
    let snapshot_files = read_tar_archive(archive_path)?;
    let mut disk_files = scan_disk_files(project_dir)?;
    if let Ok(rel_archive) = archive_path.strip_prefix(project_dir) {
        let rel_str = rel_archive.to_string_lossy().replace('\\', "/");
        disk_files.remove(&rel_str);
    }
    let snapshot_keys: BTreeSet<&String> = snapshot_files.keys().collect();
    let disk_keys: BTreeSet<&String> = disk_files.keys().collect();

    let added = disk_keys.difference(&snapshot_keys).count();
    let deleted = snapshot_keys.difference(&disk_keys).count();
    let mut modified = 0usize;
    for path in disk_keys.intersection(&snapshot_keys) {
        if snapshot_files[*path] != disk_files[*path] {
            modified += 1;
        }
    }
    Ok((modified, added, deleted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-snap-{tag}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn snapshot_and_rollback_restores_cleanly() {
        let src_dir = temp_test_dir("src");
        let restore_dir = temp_test_dir("restore");

        fs::write(src_dir.join("a.txt"), "hello file a\n").unwrap();
        fs::write(src_dir.join("sub").join("b.txt"), "hello file b\n").unwrap_or_else(|_| {
            fs::create_dir_all(src_dir.join("sub")).unwrap();
            fs::write(src_dir.join("sub").join("b.txt"), "hello file b\n").unwrap();
        });

        let session_id = format!("test-session-{}", std::process::id());
        let meta = create_snapshot(&src_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();
        assert_eq!(meta.file_count, 2);
        assert!(meta.total_size_bytes > 0);

        let res = rollback_snapshot(&session_id, Some(&restore_dir)).unwrap();
        assert_eq!(res.files_restored, 2);
        assert_eq!(
            fs::read_to_string(restore_dir.join("a.txt")).unwrap(),
            "hello file a\n"
        );
        assert_eq!(
            fs::read_to_string(restore_dir.join("sub").join("b.txt")).unwrap(),
            "hello file b\n"
        );

        let _ = fs::remove_dir_all(&src_dir);
        let _ = fs::remove_dir_all(&restore_dir);
    }

    #[test]
    fn rollback_deletes_untracked_files() {
        let src_dir = temp_test_dir("untracked");
        fs::write(src_dir.join("original.txt"), "original\n").unwrap();

        let session_id = format!("test-session-untracked-{}", std::process::id());
        create_snapshot(&src_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        // Simulate agent adding a new rogue file
        fs::write(src_dir.join("rogue.txt"), "rogue script\n").unwrap();
        assert!(src_dir.join("rogue.txt").exists());

        let res = rollback_snapshot(&session_id, Some(&src_dir)).unwrap();
        assert_eq!(res.files_restored, 1);
        assert_eq!(res.files_deleted, 1);
        assert!(!src_dir.join("rogue.txt").exists());
        assert!(src_dir.join("original.txt").exists());

        let _ = fs::remove_dir_all(&src_dir);
    }

    #[test]
    fn ignored_directories_are_excluded_from_snapshot() {
        let src_dir = temp_test_dir("ignored");

        // Ignored build/toolchain directories
        let ignored_dirs = [".git", "node_modules", "target", ".venv", "dist", "build"];
        for d in &ignored_dirs {
            let dir_path = src_dir.join(d);
            fs::create_dir_all(&dir_path).unwrap();
            fs::write(dir_path.join("file.txt"), "ignored content").unwrap();
        }

        // Legitimate source directory
        let legit_dir = src_dir.join("src");
        fs::create_dir_all(&legit_dir).unwrap();
        fs::write(legit_dir.join("main.rs"), "fn main() {}\n").unwrap();

        let session_id = format!("test-session-ignored-{}", std::process::id());
        let meta = create_snapshot(&src_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();

        assert_eq!(
            meta.file_count, 1,
            "only legit src/main.rs should be included"
        );
        let entries = inspect_snapshot_archive(&session_id).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "src/main.rs");

        let _ = fs::remove_dir_all(&src_dir);
    }

    #[test]
    fn snapshot_aborts_on_exceeded_size_limit() {
        let src_dir = temp_test_dir("size-limit");
        fs::write(src_dir.join("large.bin"), vec![0u8; 1000]).unwrap();

        let session_id = format!("test-session-size-{}", std::process::id());
        // Quota is 500 bytes, file is 1000 bytes
        let res = create_snapshot(&src_dir, &session_id, 500);

        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("exceeds maximum snapshot limit"));

        let _ = fs::remove_dir_all(&src_dir);
    }

    #[test]
    fn test_try_reflink_clone() {
        let dir = temp_test_dir("reflink");
        let src = dir.join("src.txt");
        let dst = dir.join("dst.txt");
        let payload = "reflink test payload";
        fs::write(&src, payload).unwrap();

        let res = try_reflink_clone(&src, &dst);
        assert!(res.is_ok(), "try_reflink_clone should succeed: {:?}", res);
        assert!(dst.exists(), "destination file must exist");
        let content = fs::read_to_string(&dst).unwrap();
        assert_eq!(content, payload, "destination must match test payload");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_snapshot_cyclic_directory_symlink_safety() {
        let dir = temp_test_dir("cyclic-symlink");
        fs::write(dir.join("legit.txt"), "regular content").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let _ = symlink(&dir, dir.join("self_loop"));
            let _ = symlink(dir.parent().unwrap_or(&dir), dir.join("parent_loop"));
        }

        let session_id = format!("test-cyclic-symlink-{}", std::process::id());
        let meta = create_snapshot(&dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE)
            .expect("snapshot must complete safely without cyclic loop");
        assert_eq!(meta.file_count, 1, "only legit.txt should be indexed");

        let _ = fs::remove_dir_all(&dir);
        if let Ok(root) = snapshots_root_dir() {
            let _ = fs::remove_dir_all(root.join(&session_id));
        }
    }

    #[test]
    fn test_snapshot_size_limit_directory_cleanup() {
        let src_dir = temp_test_dir("size-cleanup");
        fs::write(src_dir.join("large.bin"), vec![0u8; 1000]).unwrap();

        let session_id = format!("test-size-cleanup-{}", std::process::id());
        let res = create_snapshot(&src_dir, &session_id, 500);
        assert!(res.is_err());

        if let Ok(root) = snapshots_root_dir() {
            let session_dir = root.join(&session_id);
            assert!(
                !session_dir.exists(),
                "snapshot session directory must be deleted upon exceeding size limit"
            );
        }

        let _ = fs::remove_dir_all(&src_dir);
    }

    #[test]
    fn test_snapshot_long_path_ustar_prefix_roundtrip() {
        let mut buffer = Vec::new();
        let long_path = "nested/deeply/within/a/fairly/long/hierarchy/of/directories/that/exceeds/one/hundred/bytes/in/total/length/sample_file_name.rs";
        assert!(long_path.len() > 100 && long_path.len() <= 256);

        let test_data = b"pub fn long_path_test() -> bool { true }\n";
        let test_mode = 0o755;
        let test_mtime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1700000000);

        write_tar_entry_with_mode(&mut buffer, long_path, test_data, test_mtime, test_mode)
            .expect("write tar entry");

        assert!(buffer.len() >= 512);
        let mut header = [0u8; 512];
        header.copy_from_slice(&buffer[..512]);

        let (parsed_name, parsed_size, parsed_mode) =
            parse_tar_header_with_mode(&header).expect("parse header");

        assert_eq!(parsed_name, long_path);
        assert_eq!(parsed_size, test_data.len() as u64);
        assert_eq!(parsed_mode, test_mode);
    }
}
