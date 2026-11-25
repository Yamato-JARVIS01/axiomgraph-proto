//! Isolated Wasm32 guest worker for AxiomGraph Write-back actions.
//! Has ZERO filesystem or network capabilities; only `axiom_host::host_erp_dry_run`
//! and `axiom_host::host_erp_commit` are linked by the Wasmtime host.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action_type")]
pub enum GuestAction {
    CreatePurchaseOrderDraft {
        part_number: String,
        quantity: i64,
        target_rev: String,
        reason: String,
        idempotency_key: String,
        expected_erp_version: i64,
    },
    CreateBomRevisionRequest {
        parent_part_number: String,
        child_part_number: String,
        new_rev: String,
        reason: String,
        idempotency_key: String,
        expected_erp_version: i64,
    },
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "axiom_host")]
extern "C" {
    fn host_erp_dry_run(ptr: i32, len: i32) -> i32;
    fn host_erp_commit(ptr: i32, len: i32) -> i32;
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_erp_dry_run(_ptr: i32, _len: i32) -> i32 {
    0
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn host_erp_commit(_ptr: i32, _len: i32) -> i32 {
    0
}

/// Allocate `len` bytes in guest linear memory so the host can write an action JSON payload.
#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
    if len <= 0 {
        return 0;
    }
    let mut buf = Vec::<u8>::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr as i32
}

/// Execute dry-run inside the Wasmtime sandbox, forwarding validated payload to `host_erp_dry_run`.
#[no_mangle]
pub extern "C" fn execute_dry_run(ptr: i32, len: i32) -> i32 {
    dispatch_to_host(ptr, len, true)
}

/// Execute commit inside the Wasmtime sandbox, forwarding validated payload to `host_erp_commit`.
#[no_mangle]
pub extern "C" fn execute_commit(ptr: i32, len: i32) -> i32 {
    dispatch_to_host(ptr, len, false)
}

fn dispatch_to_host(ptr: i32, len: i32, is_dry_run: bool) -> i32 {
    if ptr <= 0 || len <= 0 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    let Ok(action) = serde_json::from_slice::<GuestAction>(slice) else {
        return -2;
    };
    let Ok(canonical) = serde_json::to_vec(&action) else {
        return -3;
    };
    unsafe {
        if is_dry_run {
            host_erp_dry_run(canonical.as_ptr() as i32, canonical.len() as i32)
        } else {
            host_erp_commit(canonical.as_ptr() as i32, canonical.len() as i32)
        }
    }
}
