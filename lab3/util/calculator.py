from enum import IntEnum


class Op(IntEnum):
    # arithmetic
    ADD = 1
    MIN = 2
    MAX = 3
    NEG = 4
    SHL = 5
    SHR = 6
    # memory
    MSTORE = 11
    MLOAD = 12
    MADD = 13
    MMIN = 14
    MMAX = 15
    MNEG = 16
    MSHL = 17
    MSHR = 18

    def __str__(self):
        return self.name

class Calculator:
    def exec(self, op, a=0, b=0):
        """Send `op` with operands a, b to the switch and return the
        result the switch sends back. Implement me."""
        raise NotImplementedError

    # ---- arithmetic ----
    def add(self, a, b): return self.exec(Op.ADD, a, b)
    def min(self, a, b): return self.exec(Op.MIN, a, b)
    def max(self, a, b): return self.exec(Op.MAX, a, b)
    def neg(self, a): return self.exec(Op.NEG, a)
    def shl(self, a): return self.exec(Op.SHL, a)  # a << 1
    def shr(self, a): return self.exec(Op.SHR, a)  # a >> 1

    # ---- memory ----
    def store(self, a): return self.exec(Op.MSTORE, a)
    def load(self): return self.exec(Op.MLOAD)

    def madd(self, a): return self.exec(Op.MADD, a)  # returns OLD mem
    def mmin(self, a): return self.exec(Op.MMIN, a)  # returns OLD mem
    def mmax(self, a): return self.exec(Op.MMAX, a)  # returns OLD mem
    def mneg(self): return self.exec(Op.MNEG)  # returns OLD mem
    def mshl(self): return self.exec(Op.MSHL)  # returns OLD mem
    def mshr(self): return self.exec(Op.MSHR)  # returns OLD mem

    # ---- compositions of basic ops ----
    def sub(self, a, b): return self.exec(Op.ADD, a, -b)
    def msub(self, a): return self.exec(Op.MADD, -a)  # returns OLD mem


INT_MAX = 2**31 - 1
INT_MIN = -(2**31)

def s32(x):
    """Wrap to signed 32-bit two's complement."""
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x & 0x80000000 else x

class CalculatorTester:
    """Test helper for a P4 calculator.

    Usage:
        c = MyCalculator()
        P4CalculatorTester(c).test(c)
    """
    def test(self, calc):
        assert calc is not None, "test() was passed None — check how calc is constructed"
        tests = [
            getattr(self, name)
            for name in type(self).__dict__
            if name.startswith("_test") and callable(getattr(self, name))
        ]
        passed = 0
        for idx, _test in enumerate(tests, 1):
            name = _test.__name__
            print(f"[{idx}] {name}")
            try:
                _test(calc)
                print("    PASS")
                passed += 1
            except AssertionError as e:
                print(f"    FAIL: {e}")
            except Exception as e:
                print(f"    ERROR: {type(e).__name__}: {e}")
        print(f"\n{passed}/{len(tests)} passed")
        return passed == len(tests)

    def _test_arith(self, c : Calculator):
        assert c.add(3, 4) == 7, f"add: got {c.add(3, 4)}"
        assert c.sub(10, 4) == 6, f"sub: got {c.sub(10, 4)}"
        assert c.add(-5, 5) == 0, f"add neg: got {c.add(-5, 5)}"
        assert c.sub(0, 7) == -7, f"sub to neg: got {c.sub(0, 7)}"
        assert c.add(7, 0) == 7, "additive identity"
        assert c.add(3, 4) == c.add(4, 3), "add must commute"
        assert c.add(c.sub(20, 6), 6) == 20, "sub then add round-trips"

    def _test_neg(self, c : Calculator):
        assert c.neg(0) == 0
        assert c.neg(5) == -5 and c.neg(-5) == 5
        assert c.neg(c.neg(7)) == 7, "neg is an involution"
        assert c.add(9, c.neg(9)) == 0, "x + (-x) == 0"
        # -INT_MIN overflows back to INT_MIN in two's complement
        assert c.neg(INT_MIN) == INT_MIN, f"neg(INT_MIN): got {c.neg(INT_MIN)}"
        assert c.neg(INT_MAX) == INT_MIN + 1, f"neg(INT_MAX): got {c.neg(INT_MAX)}"


    def _test_shift(self, c : Calculator):
        assert c.shl(5) == 10, f"shl: got {c.shl(5)}"
        assert c.shr(20) == 10, f"shr: got {c.shr(20)}"
        assert c.shr(1) == 0, f"shr to 0: got {c.shr(1)}"
        assert c.shr(3) == 1, f"shr floor: got {c.shr(3)}"

    def _test_shl_is_double(self, c : Calculator):
        # Unambiguous cross-check: x << 1 must equal x + x, even on wrap.
        for x in [0, 1, 5, -3, 1000, INT_MAX, INT_MIN, -1]:
            assert c.shl(x) == c.add(x, x), f"shl({x}) != add({x},{x})"

    def _test_shr_sign(self, c : Calculator):
        # shr of a NEGATIVE value is implementation-defined: arithmetic
        # (signed, sign-extends) vs logical (unsigned, zero-fills). We
        # don't pick one — we detect it, verify self-consistency, report.
        r1, r2 = c.shr(-2), c.shr(-1)
        if (r1, r2) == (-1, -1): return     # arithmetic shr (sign-extend)
        if (r1, r2) == (INT_MAX, INT_MAX): return # logical shr (0-extend)
        raise AssertionError(f"shr(-2)={r1}, shr(-1)={r2}: matches neither arithmetic "
                             f"(-1,-1) nor logical ({INT_MAX},{INT_MAX})")

    def _test_minmax(self, c : Calculator):
        pairs = [(3, 9), (-2, 5), (7, 7), (-10, -3), (INT_MIN, INT_MAX), (0, -1)]
        for a, b in pairs:
            mn, mx = c.min(a, b), c.max(a, b)
            assert mn == min(a, b), f"min({a},{b}): got {mn}"
            assert mx == max(a, b), f"max({a},{b}): got {mx}"
            # partition identity: min + max == a + b
            assert c.add(mn, mx) == c.add(a, b), f"min+max != a+b for {a},{b}"
        for a, b in [(3, 9), (-2, 5), (-10, -3), (0, 100)]: # duality: min(a,b) == -max(-a,-b)
            mn,mx = c.min(a, b), c.neg(c.max(c.neg(a), c.neg(b)))
            assert mn == mx, f"min/max duality failed for {a},{b}"

    def _test_overflow(self, c : Calculator):
        assert c.add(INT_MAX, 1) == INT_MIN, f"INT_MAX+1: got {c.add(INT_MAX, 1)}"
        assert c.add(INT_MIN, -1) == INT_MAX, f"INT_MIN-1: got {c.add(INT_MIN, -1)}"
        assert c.sub(INT_MIN, 1) == INT_MAX, f"sub INT_MIN-1: got {c.sub(INT_MIN, 1)}"
        assert c.add(INT_MIN, INT_MIN) == 0, f"INT_MIN+INT_MIN: got {c.add(INT_MIN, INT_MIN)}"
        assert c.add(INT_MAX, INT_MAX) == -2, f"INT_MAX+INT_MAX: got {c.add(INT_MAX, INT_MAX)}"
        assert c.shl(INT_MIN) == 0, f"shl(INT_MIN): got {c.shl(INT_MIN)}"
        assert c.shl(INT_MAX) == -2, f"shl(INT_MAX): got {c.shl(INT_MAX)}"

    # ---- memory ----
    def _test_mem_basic(self, c : Calculator):
        for v in [42, -1, 0, INT_MAX, INT_MIN]:
            c.store(v)
            assert c.load() == v, f"store/load {v}: got {c.load()}"

    def _test_mem_contract(self, c : Calculator):
        # Every fetch-and-modify op must return the OLD mem, then leave the
        # NEW mem correct. shr case uses a non-negative mem so the expected
        # value is unambiguous (see _test_shr_sign for the negative case).
        cases = [
            ("madd",   10, lambda: c.madd(5),  s32(10 + 5)),
            ("madd-",   3, lambda: c.madd(-8), s32(3 - 8)),
            ("msub",   15, lambda: c.msub(3),  s32(15 - 3)),
            ("mneg",    7, lambda: c.mneg(),   -7),
            ("mneg0",   0, lambda: c.mneg(),   0),
            ("mshl",   -3, lambda: c.mshl(),   s32(-3 << 1)),
            ("mshr",   20, lambda: c.mshr(),   10),
            ("mmin<",  10, lambda: c.mmin(3),  3),
            ("mmin>",  10, lambda: c.mmin(50), 10),
            ("mmax>",  10, lambda: c.mmax(50), 50),
            ("mmax<",  10, lambda: c.mmax(3),  10),
        ]
        for label, mem, call, expected in cases:
            c.store(mem)
            old = call()
            assert old == mem, f"{label}: fetch should return old mem {mem}, got {old}"
            assert c.load() == expected, f"{label}: mem should be {expected}, got {c.load()}"

    def _test_mem_matches_stateless(self, c : Calculator):
        # The memory op and its stateless counterpart should agree on the
        # NEW mem value. Pure dataplane-vs-dataplane: no Python assumptions,
        # so it catches "two actions, same op, different implementation".
        for M, a in [(10, 5), (-4, 9), (7, -7), (INT_MAX, 1), (INT_MIN, -1)]:
            for label, mut, ref in [
                ("madd/add", lambda: c.madd(a), lambda: c.add(M, a)),
                ("mmin/min", lambda: c.mmin(a), lambda: c.min(M, a)),
                ("mmax/max", lambda: c.mmax(a), lambda: c.max(M, a)),
                ("mneg/neg", lambda: c.mneg(),  lambda: c.neg(M)),
                ("mshl/shl", lambda: c.mshl(),  lambda: c.shl(M)),
                ("mshr/shr", lambda: c.mshr(),  lambda: c.shr(M)),
            ]:
                c.store(M)
                old = mut()
                assert old == M, f"{label}: fetch should return {M}, got {old}"
                assert c.load() == ref(), f"{label} mismatch at M={M}, a={a}"

    def _test_mneg_involution(self, c : Calculator):
        c.store(7)
        assert c.mneg() == 7 and c.load() == -7
        assert c.mneg() == -7 and c.load() == 7
        c.store(INT_MIN)
        assert c.mneg() == INT_MIN, "mneg returns old"
        assert c.load() == INT_MIN, "neg(INT_MIN) == INT_MIN (overflow fixpoint)"

    def _test_mem_reduce(self, c : Calculator):
        # Reduce a stream through a single cell via fetch-and-modify.
        data = [4, -7, 19, 19, 0, -100, 55, 3]
        c.store(0)
        for x in data: c.madd(x)
        assert c.load() == sum(data), f"madd sum: got {c.load()}"
        c.store(INT_MIN)
        for x in data: c.mmax(x)
        assert c.load() == max(data), f"mmax reduce: got {c.load()}"
        c.store(INT_MAX)
        for x in data: c.mmin(x)
        assert c.load() == min(data), f"mmin reduce: got {c.load()}"

    def _test_mem_powers_of_two(self, c : Calculator):
        c.store(1)
        for n in range(1, 31):
            old = c.mshl()
            assert old == 2 ** (n - 1), f"mshl old at step {n}: got {old}"
            assert c.load() == 2 ** n, f"2**{n}: got {c.load()}"
        c.store(2 ** 30)
        c.mshl()
        assert c.load() == INT_MIN, f"2**31 must wrap to INT_MIN: got {c.load()}"

    def _test_fib(self, c : Calculator):
        # Build Fibonacci using only fetch-and-add on a single memory cell.
        # mem holds the running value; `prev` carries the term to add next.
        c.store(1)  # mem = fib(2) = 1
        prev = 1  # fib(1)
        seq = [1, 1]  # fib(1), fib(2)
        for _ in range(8):
            old = c.madd(prev)  # mem += prev, returns old mem (= current fib)
            new = c.load()  # new mem = next fib
            seq.append(new)
            prev = old  # next term to add is the previous fib
        expected = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]
        print(seq)
        assert seq == expected, f"fib: got {seq}"
