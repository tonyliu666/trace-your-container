from bcc import BPF
b = BPF(text = """
TRACEPOINT_PROBE(raw syscalls, sys_enter)
{
    bpf_trace_printk("Hello world\\n");
}
""")

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))