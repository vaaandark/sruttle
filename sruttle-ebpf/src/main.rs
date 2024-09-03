#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{kprobe, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::ProbeContext,
};

mod binding;

use crate::binding::cfs_rq;
use sruttle_common::*;

#[map]
static PACKETLOGS: PerCpuArray<PacketLog> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

#[kprobe]
pub fn sruttle(ctx: ProbeContext) -> u32 {
    match try_sruttle(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sruttle(ctx: ProbeContext) -> Result<u32, u32> {
    let cfs_rq: *const cfs_rq = ctx.arg(0).ok_or(1u32)?;
    let rq = unsafe { bpf_probe_read_kernel(&(*cfs_rq).rq) }.or(Err(1u32))?;
    let clock = unsafe { bpf_probe_read_kernel(&(*rq).clock) }.or(Err(1u32))?;
    let throttled_clock =
        unsafe { bpf_probe_read_kernel(&(*cfs_rq).throttled_clock) }.or(Err(1u32))?;
    let throttled_us = clock - throttled_clock;
    let tg = unsafe { bpf_probe_read_kernel(&(*cfs_rq).tg) }.or(Err(1u32))?;
    let cgroup = unsafe { bpf_probe_read_kernel(&(*tg).css.cgroup) }.or(Err(1u32))?;
    let kn = unsafe { bpf_probe_read_kernel(&(*cgroup).kn) }.or(Err(1u32))?;
    let cgroup_inode = unsafe { bpf_probe_read_kernel(&(*kn).id.__bindgen_anon_1.ino) }.or(Err(1u32))?;

    let packet_log = unsafe { PACKETLOGS.get_ptr_mut(0).ok_or(1u32)?.as_mut() }.ok_or(1u32)?;
    packet_log.throttled_us = throttled_us;
    packet_log.cgroup_inode = cgroup_inode;
    EVENTS.output(&ctx, packet_log, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
