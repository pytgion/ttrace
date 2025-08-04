#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    __u32 pid;
    ssize_t bytes;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, pid_t);
} pid_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct file *);
} active_writes SEC(".maps");



SEC("kprobe/ksys_write")
int ttrace_write_entry(struct pt_regs *ctx) {
    u32 key = 0;
    pid_t *target_pid;
    u64 id = bpf_get_current_pid_tgid();
    pid_t current_pid = (pid_t)id;

    // Hedef PID kontrolü
    target_pid = bpf_map_lookup_elem(&pid_map, &key);
    if (!target_pid || *target_pid != current_pid) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int fd = PT_REGS_PARM1(ctx);

    struct file *file;
    struct files_struct *files;
    struct fdtable *fdt;
    struct file **fd_array;

    files = BPF_CORE_READ(task, files);
    if (!files) return 0;

    fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return 0;
    
    fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) return 0;

    if (bpf_core_read(&file, sizeof(&file), &fd_array[fd])) {
        return 0;
    }

    bpf_map_update_elem(&active_writes, &id, &file, BPF_ANY);
    return 0;
}


SEC("kretprobe/ksys_write")
int ttrace_write_exit(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct file **file_pp;

    file_pp = bpf_map_lookup_elem(&active_writes, &id);
    if (!file_pp) {
        return 0;
    }

    bpf_map_delete_elem(&active_writes, &id);

    struct event event = {};
    event.pid = (pid_t)id;
    event.bytes = PT_REGS_RC(ctx);

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    struct file *file = *file_pp;
    if (file) {
        const unsigned char *filename_ptr = BPF_CORE_READ(file, f_path.dentry, d_name.name);
        bpf_core_read_str(&event.filename, sizeof(event.filename),filename_ptr);
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
