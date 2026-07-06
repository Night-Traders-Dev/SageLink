proc fib(n):
    if n <= 1:
        return n
    return fib(n-1) + fib(n-2)

proc run_fib():
    let res = fib(25)
    print res

run_fib()
