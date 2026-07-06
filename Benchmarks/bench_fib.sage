proc fib(n):
    if n <= 1:
        return n
    
    # Run GC every so often to avoid OOM in slow VMs
    if n == 20:
        gc_collect()
    end
        
    return fib(n-1) + fib(n-2)

proc run_fib():
    let res = fib(25)
    print res
    
    print("GC Stats: Native GC is managing memory.")

run_fib()
