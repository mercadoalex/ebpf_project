# ebpf_project
Make your observability system from scratch with eBPF and Ubuntu
...and C, Python, Flask, JS, and a bunch of other tools and trechnologies.

## Description
This project demonstrates a simple eBPF program that counts the number of times the `execve` syscall is executed on your system. It uses a BPF array map to store the counter and prints the command name to the kernel trace pipe for observability.

## Author
Alejandro Mercado 

## Project Structure
```
ebpf_project/
├── ebpf/
│   └── click_counter.bpf.c   # eBPF program source code
├── scripts/                  # (Optional) Python or shell scripts to load/run the eBPF program
├── README.md                 # Project documentation
```

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mercadoalex/ebpf_project.git
   cd ebpf_project
   ```

2. **Install dependencies:**
   - Ensure you have [BCC](https://github.com/iovisor/bcc) and its Python bindings installed.
   - You may need kernel headers and root privileges.

3. **Build and run:**
   - Use a Python script or BCC tools to load `click_counter.bpf.c` and attach it to the `execve` tracepoint.
   - Example (with Python):
     ```python
     from bcc import BPF
     b = BPF(src_file="ebpf/click_counter.bpf.c")
     b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace")
     print("Tracing execve syscalls... Ctrl-C to end.")
     b.trace_print()
     ```

## Blog

For a detailed walkthrough, see the related blog post on [Medium](https://alexmarket.medium.com/).
