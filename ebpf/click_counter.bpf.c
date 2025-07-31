#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

/*
 * Define a BPF array map with 1 entry.
 * - Name: click_count_map
 * - Key type: u32 (always 0)
 * - Value type: u64 (the counter)
 * BCC macro BPF_ARRAY creates the map for you.
 */
BPF_ARRAY(click_count_map, u64, 1);

/*
 * Tracepoint handler for the 'execve' syscall (program execution).
 * This function is attached from Python using bpf.attach_tracepoint().
 * Every time a program is executed (e.g., ls, cat, etc.), this function runs and increments the counter.
 * It also prints the command name to the kernel trace pipe for observability.
 */
int trace(struct trace_event_raw_sys_enter *ctx) {
    u32 key = 0; // Only one entry in the map, always use key 0
    u64 *count = click_count_map.lookup(&key); // Get pointer to the counter
    if (count) {
        __sync_fetch_and_add(count, 1); // Atomically increment the counter
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm)); // Get the command name
        bpf_trace_printk("execve: %s\n", comm);    // Print command name to trace_pipe
    }
    return 0; // Required return value for BPF programs
}