use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
// 1. Manually define the Linux ABI statx struct and constants
// since they are missing from the musl libc bindings.
const STATX_BTIME: u32 = 0x00000800;

#[repr(C)]
struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

#[repr(C)]
struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: [u16; 1],
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub __spare2: u64,
    pub __spare3: [u64; 12],
}

pub fn get_linux_btime(path: &std::path::Path) -> Option<u64> {
    // Unix paths are technically raw bytes, not guaranteed to be valid UTF-8.
    // OsStrExt allows us to safely convert it to a CString.
    let path_c = CString::new(path.as_os_str().as_bytes()).ok()?;

    // Create a zeroed out struct to hand to the kernel
    let mut stx: Statx = unsafe { std::mem::zeroed() };

    unsafe {
        // Make the raw syscall directly to the Linux kernel, bypassing the C library
        let res = libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            path_c.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            STATX_BTIME,
            &mut stx as *mut Statx,
        );

        // If the syscall succeeded (0) and the kernel filled in the btime mask
        if res == 0 && (stx.stx_mask & STATX_BTIME) != 0 {
            return Some(stx.stx_btime.tv_sec as u64);
        }
    }

    None
}
