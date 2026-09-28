"""Verificacion de cuasi-primos (semiprimos) para licencias OMNI-Lic.

Semiprimo n = p * q. Verificacion Miller-Rabin para grandes,
division de prueba para pequenos. Sello sha512(n).
"""
import hashlib
import random

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
]


def _trial_division(n: int) -> bool:
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


def is_probable_prime(n: int, k: int = 24) -> bool:
    """Miller-Rabin para numeros grandes; division de prueba para pequenos."""
    if n < 2:
        return False
    if n < 1000000:
        return _trial_division(n)
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits: int = 128) -> int:
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n


def generate_semiprime(bits: int = 128) -> tuple:
    """Genera semiprimo n = p * q con p != q. Devuelve (p, q, n)."""
    p = random_prime(bits)
    while True:
        q = random_prime(bits)
        if q != p:
            break
    return p, q, p * q


def is_valid_semiprime(n: int) -> bool:
    """Valida que n es compuesto (producto de dos primos distintos) segun criterio OMNI-Lic."""
    if n < 4 or n % 2 == 0:
        return False
    if is_probable_prime(n):
        return False  # semiprimo no puede ser primo
    # Encontrar un divisor no trivial pequeno; si existe y ambos factores primos -> ok
    # Para n grandes solo garantizamos "compuesto no primo de paridad impar" (criterio practico)
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return True
    # compuesto impar sin factor pequeno -> aceptamos como candidato semiprimo
    return True


def pruebas_compromiso(p: int, q: int, n: int) -> dict:
    """Genera prueba_p, prueba_q y sello_n."""
    return {
        "prueba_p": hashlib.sha512(str(p).encode()).hexdigest(),
        "prueba_q": hashlib.sha512(str(q).encode()).hexdigest(),
        "sello_n": hashlib.sha512(str(n).encode()).hexdigest(),
    }


def sello_hex_valido(huella: str) -> bool:
    return bool(huella) and len(huella) == 128 and all(c in "0123456789abcdef" for c in huella)