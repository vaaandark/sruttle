#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketLog {
    pub cgroup_inode: u32,
    pub throttled_us: u64,
}
