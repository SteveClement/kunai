#[allow(unused_imports)]
use super::*;
#[allow(unused_imports)]
use aya_bpf::programs::ProbeContext;
use aya_bpf::{helpers::bpf_get_prandom_u32, maps::LruHashMap, BpfContext};
use kunai_common::co_re::task_struct;
use kunai_macros::rename_function;

#[map]
static mut DEBUG_EXECVE_TRACKING: LruHashMap<u128, ExecveEvent> =
    LruHashMap::with_max_entries(4096, 0);

#[map]
static mut DEBUG_BPRM_EXECVE_ARGS: LruHashMap<u64, co_re::linux_binprm> =
    LruHashMap::with_max_entries(1024, 0);

#[repr(C)]
enum Error {
    Foo,
    Bar,
}

impl Error {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Foo => "foo",
            Self::Bar => "bar",
        }
    }
}

// this guy gives us the real executable path (i.e. a script for instance)
// we need to hook at another point in order to get the interpreter. For
// instance at exit of bprm_execve.
#[kprobe]
pub fn security_bprm_check(ctx: ProbeContext) -> u32 {
    unsafe {
        let err = {
            if bpf_get_prandom_u32() % 2 == 0 {
                Error::Bar
            } else {
                Error::Foo
            }
        };
        error!(&ctx, "{}", err.as_str());
        0
    }
    /*match unsafe { try_security_bprm_check(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }*/
}

unsafe fn try_security_bprm_check(ctx: &ProbeContext) -> ProbeResult<()> {
    let linux_binprm = co_re::linux_binprm::from_ptr(ctx.arg(0).unwrap_or(core::ptr::null()));
    let ts = co_re::task_struct::current();
    let task_uuid = ts.uuid();

    if DEBUG_EXECVE_TRACKING.get_ptr_mut(&task_uuid).is_some() {
        // security_bprm_check is running in a loop
        // we aleady processed the higher call giving executable
        return Ok(());
    }

    // we keep track of linux_binprm
    if !linux_binprm.is_null() {
        ignore_result!(DEBUG_BPRM_EXECVE_ARGS.insert(&bpf_task_tracking_id(), &linux_binprm, 0))
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<ExecveEvent>()?;

    if let Some(file) = linux_binprm.file() {
        event
            .data
            .executable
            .core_resolve_file(&file, MAX_PATH_DEPTH)?;
    }

    DEBUG_EXECVE_TRACKING
        .insert(&task_uuid, event, 0)
        .map_err(|_| MapError::InsertFailure)?;

    Ok(())
}

// for kernel < 5.9 bprm_execve does not exists, we must replace the hook
// by __do_execve_file (done in program loader)
#[kprobe(function = "debug.execve.exit.bprm_execve")]
pub fn bprm_execve(ctx: ProbeContext) -> u32 {
    0
    /*match unsafe { try_bprm_execve(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }*/
}

#[inline(always)]
unsafe fn execve_event<C: BpfContext>(ctx: &C, rc: i32) -> ProbeResult<()> {
    let linux_binprm = DEBUG_BPRM_EXECVE_ARGS
        .get(&bpf_task_tracking_id())
        .ok_or(MapError::GetFailure)?;

    let ts = task_struct::current();

    let task_uuid = ts.uuid();

    let event = DEBUG_EXECVE_TRACKING
        .get_ptr_mut(&task_uuid)
        .ok_or(MapError::GetFailure)?;

    let event = &mut (*event);

    // initializing event
    event.init_from_current_task(Type::Execve)?;

    // file should not be null here
    // we are getting interpreter which is set to the file attribute by exec_binprm kernel function
    if let Some(file) = linux_binprm.file() {
        event
            .data
            .interpreter
            .core_resolve_file(&file, MAX_PATH_DEPTH)?;
    }

    event.data.rc = rc;

    let arg_start = core_read_kernel!(ts, mm, arg_start)?;
    let arg_len = core_read_kernel!(ts, mm, arg_len)?;

    // parsing argv
    if event
        .data
        .argv
        .read_user_at(arg_start as *const u8, arg_len as u32)
        .is_err()
    {
        //error!(ctx, "failed to read argv")
    }

    // cgroup parsing
    let cgroup = core_read_kernel!(ts, sched_task_group, css, cgroup)?;
    if let Err(e) = event.data.cgroup.resolve(cgroup) {
        error!(ctx, "failed to resolve cgroup: {}", e.description());
    }

    pipe_event(ctx, event);

    // we use a LruHashMap so we can safely ignore result
    ignore_result!(DEBUG_EXECVE_TRACKING.remove(&task_uuid));

    Ok(())
}

unsafe fn try_bprm_execve(ctx: &ProbeContext) -> ProbeResult<()> {
    let rc = ctx.ret().unwrap_or(-1);

    // execve failed
    if rc < 0 {
        return Ok(());
    }

    execve_event(ctx, rc)
}
