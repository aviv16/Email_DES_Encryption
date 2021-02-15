"""
Implement the following routine:

	(Integer, Integer) pair(Integer)
such that pair(d) will return (p,a) containing a safe prime p with
d bits and a generator a for Z∗p.
"""
import Crypto.Util.number as num
import random


def pair(s):
    safe_prime = 0
    while (True):
        p = num.getPrime(s)
        safe_prime = 2 * p + 1
        if (num.isPrime(safe_prime)):
            break
    while (True):
        a = random.randint(2, safe_prime - 1)
        if ((safe_prime - 1) % a != 1):
            break

    return safe_prime, a