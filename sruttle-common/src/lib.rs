#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketLog {
    pub throttled_us: u64,
    pub cgroup_id: u64,
}
