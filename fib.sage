proc fib(n):
    if n <= 1:
        return n
    return fib(n-1) + fib(n-2)

proc run():
    let res = fib(35)
    print "Fib(35) = "
    print res
run()
