#include <iostream>
#include <csignal>
#include <string>
#include <unistd.h>
#include <iomanip>
#include <cstdint>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile bool running = true;

struct event {
    uint32_t pid;
    ssize_t bytes;
    char comm[16];
    char filename[256];
};

static void sig_handler(int sig) {
    running = false;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct event *e = (struct event *)data;
    if (e->bytes < 0) {
        return;
    }
    std::cout << std::left
        << std::setw(16) << e->comm
        << std::setw(8) << e->pid
        << std::setw(8) << e->bytes
        << e->filename << std::endl;
}

int main(int argc, char** argv) {
    struct bpf_object *obj = NULL;
    struct perf_buffer *pb = NULL;
    struct bpf_link *kprobe_link = NULL;
    struct bpf_link *kretprobe_link = NULL;
    int err = 0;
    pid_t target_pid = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (argc < 2) {
        std::cerr << "usage: sudo ./ttrace <pid>" << std::endl;
        return 1;
    }
    
    try {
        target_pid = std::stoi(argv[1]);
    } catch (const std::exception& e) {
        std::cerr << "Invalid PID: " << argv[1] << std::endl;
        return 1;
    }

    do {
        obj = bpf_object__open_file("ttrace.bpf.o", NULL);
        if (!obj) {
            std::cerr << "HATA: BPF object file could not open." << std::endl;
            err = -1; break;
        }

        err = bpf_object__load(obj);
        if (err) {
            std::cerr << "ERROR: BPF object could not load: " << err << std::endl;
            break;
        }
        
        struct bpf_map *pid_map = bpf_object__find_map_by_name(obj, "pid_map");
        uint32_t key = 0;
        err = bpf_map_update_elem(bpf_map__fd(pid_map), &key, &target_pid, BPF_ANY);
        if (err) {
            std::cerr << "ERROR: pid_map could not update: " << err << std::endl;
            break;
        }

        struct bpf_program *prog_entry = bpf_object__find_program_by_name(obj, "ttrace_write_entry");
        kprobe_link = bpf_program__attach(prog_entry);
        if (!kprobe_link) {
            err = -1;
            std::cerr << "Error: kprobe (ttrace_write_entry) couldn't connect." << std::endl;
            break;
        }

        struct bpf_program *prog_exit = bpf_object__find_program_by_name(obj, "ttrace_write_exit");
        kretprobe_link = bpf_program__attach(prog_exit);
        if (!kretprobe_link) {
            err = -1;
            std::cerr << "ERROR: kretprobe (ttrace_write_exit) couldn't connect." << std::endl;
            break;
        }

        int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
        pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);
        if (!pb) {
            err = -1;
            std::cerr << "ERROR! failed initialize perf_buffer." << std::endl;
            break;
        }

        std::cout << std::left
            << std::setw(16) << "COMM"
            << std::setw(8) << "PID"
            << std::setw(8) << "BYTES"
            << "FILE" << std::endl;
        

        while (running) {
            err = perf_buffer__poll(pb, 100);
            if (err < 0 && err != -EINTR) {
                std::cerr << "ERROR! expecting data form perf_buffer: " << strerror(-err) << std::endl;
                break;
            }
        }
    } while (0);

    std::cout << "\nClearing Resources..." << std::endl;
    perf_buffer__free(pb);
    bpf_link__destroy(kretprobe_link);
    bpf_link__destroy(kprobe_link);
    bpf_object__close(obj);
    
    return -err;
}
