
class Collectives:
    def AllReduce(self, input: list[int], output: list[int], op : str = "sum"):
        raise NotImplementedError

    def ReduceScatter(self, input: list[int], output: list[int]):
        raise NotImplementedError

    def AllGather(self, input: list[int], output: list[int]):
        raise NotImplementedError

class Test:
  # ======================================================================
  # Collective input patterns from which we can deterministically obtain
  # the correct output for any given rank, world size and input size
  # ======================================================================

  class pattern:
    @staticmethod
    def ones(rank, world, size):
        """All 1s.   rank r sends [1, 1, ...].
        e.g. world=3, size=4 -> every rank: [1, 1, 1, 1]   (allreduce+sum: [3,3,3,3])
        """
        return [1] * size

    @staticmethod
    def ranks(rank, world, size):
        """Each rank sends its own rank number.
        e.g. world=4, size=3 -> r0:[0,0,0] r1:[1,1,1] r2:[2,2,2] r3:[3,3,3]
                                (allreduce+sum: [6,6,6])
        """
        return [rank] * size

    @staticmethod
    def iota(rank, world, size):
        """The ramp 0..size-1, same on every rank.
        e.g. world=3, size=4 -> every rank: [0, 1, 2, 3]   (allreduce+sum: [0,3,6,9])
        """
        return list(range(size))

    @staticmethod
    def iota_rot(rank, world, size):
        """The ramp rotated left by the rank (wraps with mod size).
        e.g. world=4, size=3 -> r0:[0,1,2] r1:[1,2,0] r2:[2,0,1] r3:[0,1,2]
                                (allreduce+sum: [3,4,5])
        """
        return [(i + rank) % size for i in range(size)]

    @staticmethod
    def powers(rank, world, size):
        """Each rank sends 2**rank.
        e.g. world=3, size=4 -> r0:[1,..] r1:[2,..] r2:[4,..]
                                (allreduce+sum: [7,7,7,7] = 2**world - 1)
        """
        return [1 << rank] * size

    @staticmethod
    def signs(rank, world, size):
        """Signed rank: (-1)**rank * rank, same in every slot.
        e.g. world=4, size=3 -> r0:[0,..] r1:[-1,..] r2:[2,..] r3:[-3,..]
                                (allreduce+sum: [-2,-2,-2])
        """
        return [(-1) ** rank * rank] * size

    @staticmethod
    def signs_alt(rank, world, size):
        """Sign alternates by position, magnitude is the rank.
        e.g. world=3, size=4 -> r0:[0,0,0,0] r1:[1,-1,1,-1] r2:[2,-2,2,-2]
                                (allreduce+sum: [3,-3,3,-3])
        """
        return [(-1) ** i * rank for i in range(size)]

    @staticmethod
    def signs_alt_ramp(rank, world, size):
        """Sign alternates by position, magnitude grows with position AND rank.
        e.g. world=3, size=4 -> r0:[-1,2,-3,4] r1:[-2,3,-4,5] r2:[-3,4,-5,6]
                                (allreduce+sum: [-6,9,-12,15])
        """
        return [(-1) ** (i + 1) * (rank + i + 1) for i in range(size)]


  # ======================================================================
  # Collectives reference logic. Each accepts an input pattern, rank of
  # interest, world size, and input size. It generates input for all ranks,
  # runs the operation and returns (input, expected_output) for the
  # provided rank
  # ======================================================================
  @staticmethod
  def _reduce(vals, op):
      if op == "sum":
          return sum(vals)
      if op == "min":
          return min(vals)
      if op == "max":
          return max(vals)
      if op == "avg":
          return sum(vals) // len(vals)   # floor division; len(vals) == world
      raise ValueError(f"unknown op {op!r}")

  @staticmethod
  def allreduce(pattern, rank, world, size, op="sum"):
      """Reduce every slot across all ranks; everyone gets the full result."""
      a = pattern(rank, world, size)
      b = [Test._reduce([pattern(r, world, size)[i] for r in range(world)], op)
          for i in range(size)]
      return a, b

  @staticmethod
  def reduce_scatter(pattern, rank, world, size, op="sum"):
      """Reduce every slot across all ranks (as in allreduce), then keep only
      this rank's contiguous slice of the result."""
      assert size % world == 0, f"reduce_scatter needs size % world == 0 (size={size}, world={world})"
      a = pattern(rank, world, size)
      full = [Test._reduce([pattern(r, world, size)[i] for r in range(world)], op)
              for i in range(size)]
      chunk = size // world
      b = full[rank * chunk:(rank + 1) * chunk]
      return a, b

  @staticmethod
  def allgather(pattern, rank, world, size):
      """No reduction: concatenate every rank's input in rank order."""
      a = pattern(rank, world, size)
      b = [x for r in range(world) for x in pattern(r, world, size)]
      return a, b

  # ======================================================================
  # The following functions are convenient wrappers of the above
  # Size is always the INPUT size. For allreduce input_size = output_size
  # For reducescatter input_size = output_size * world
  # For allgather input_size = output_size / world
  # ======================================================================

  class data:
    # ---- allreduce ----
    @staticmethod
    def ar_ones(rank, world, size, op="sum"):           return Test.allreduce(Test.pattern.ones, rank, world, size, op)
    @staticmethod
    def ar_ranks(rank, world, size, op="sum"):          return Test.allreduce(Test.pattern.ranks, rank, world, size, op)
    @staticmethod
    def ar_iota(rank, world, size, op="sum"):           return Test.allreduce(Test.pattern.iota, rank, world, size, op)
    @staticmethod
    def ar_iota_rot(rank, world, size, op="sum"):       return Test.allreduce(Test.pattern.iota_rot, rank, world, size, op)
    @staticmethod
    def ar_powers(rank, world, size, op="sum"):         return Test.allreduce(Test.pattern.powers, rank, world, size, op)
    @staticmethod
    def ar_signs(rank, world, size, op="sum"):          return Test.allreduce(Test.pattern.signs, rank, world, size, op)
    @staticmethod
    def ar_signs_alt(rank, world, size, op="sum"):      return Test.allreduce(Test.pattern.signs_alt, rank, world, size, op)
    @staticmethod
    def ar_signs_alt_ramp(rank, world, size, op="sum"): return Test.allreduce(Test.pattern.signs_alt_ramp, rank, world, size, op)

    # ---- reduce_scatter (needs size % world == 0) ----
    @staticmethod
    def rs_ones(rank, world, size, op="sum"):           return Test.reduce_scatter(Test.pattern.ones, rank, world, size, op)
    @staticmethod
    def rs_ranks(rank, world, size, op="sum"):          return Test.reduce_scatter(Test.pattern.ranks, rank, world, size, op)
    @staticmethod
    def rs_iota(rank, world, size, op="sum"):           return Test.reduce_scatter(Test.pattern.iota, rank, world, size, op)
    @staticmethod
    def rs_iota_rot(rank, world, size, op="sum"):       return Test.reduce_scatter(Test.pattern.iota_rot, rank, world, size, op)
    @staticmethod
    def rs_powers(rank, world, size, op="sum"):         return Test.reduce_scatter(Test.pattern.powers, rank, world, size, op)
    @staticmethod
    def rs_signs(rank, world, size, op="sum"):          return Test.reduce_scatter(Test.pattern.signs, rank, world, size, op)
    @staticmethod
    def rs_signs_alt(rank, world, size, op="sum"):      return Test.reduce_scatter(Test.pattern.signs_alt, rank, world, size, op)
    @staticmethod
    def rs_signs_alt_ramp(rank, world, size, op="sum"): return Test.reduce_scatter(Test.pattern.signs_alt_ramp, rank, world, size, op)

    # ---- allgather (no op) ----
    @staticmethod
    def ag_ones(rank, world, size):           return Test.allgather(Test.pattern.ones, rank, world, size)
    @staticmethod
    def ag_ranks(rank, world, size):          return Test.allgather(Test.pattern.ranks, rank, world, size)
    @staticmethod
    def ag_iota(rank, world, size):           return Test.allgather(Test.pattern.iota, rank, world, size)
    @staticmethod
    def ag_iota_rot(rank, world, size):       return Test.allgather(Test.pattern.iota_rot, rank, world, size)
    @staticmethod
    def ag_powers(rank, world, size):         return Test.allgather(Test.pattern.powers, rank, world, size)
    @staticmethod
    def ag_signs(rank, world, size):          return Test.allgather(Test.pattern.signs, rank, world, size)
    @staticmethod
    def ag_signs_alt(rank, world, size):      return Test.allgather(Test.pattern.signs_alt, rank, world, size)
    @staticmethod
    def ag_signs_alt_ramp(rank, world, size): return Test.allgather(Test.pattern.signs_alt_ramp, rank, world, size)

  # every function defined under class pattern, in definition order
  PATTERNS = [fn for name, fn in vars(pattern).items()
              if callable(fn) and not name.startswith("__")]

  # ======================================================================
  # Convenient test runners. Each one will run its corresponding collective
  # over all patters under test.pattern
  # ======================================================================
  @staticmethod
  def test_allreduce(coll, rank, world, size, ops=["sum", "min", "max", "avg"], show_errors=10):
      Test.test_allreduce_all(coll, rank, world, size, ["sum"], show_errors)

  @staticmethod
  def test_allreduce_all(coll, rank, world, size, ops=("sum", "min", "max", "avg"), show_errors=10):
      for op in ops:
          for pattern in Test.PATTERNS:
            inp, expected = Test.allreduce(pattern, rank, world, size, op)
            out = [0] * len(expected)
            coll.AllReduce(inp, out, op)
            if list(out) != expected:
                wrong = [(i, e, g) for i, (e, g) in enumerate(zip(expected, out)) if e != g]
                print(
                    f"@rank.{rank} AllReduce/{op}/{pattern.__name__} -- FAIL ({len(wrong)} wrong)"
                )
                n = len(wrong) if show_errors is None else show_errors
                for i, e, g in wrong[:n]:
                    print(f"  pos {i}: expected {e} got {g}")
                if n < len(wrong):
                    print(f"  ... and {len(wrong) - n} more")
            else:
              print(f"@rank.{rank} AllReduce/{op}/{pattern.__name__} -- PASS")

  @staticmethod
  def test_reducescatter(coll, rank, world, size, show_errors=10):
      for pattern in Test.PATTERNS:
          inp, expected = Test.reduce_scatter(pattern, rank, world, size)
          out = [0] * len(expected)
          coll.ReduceScatter(inp, out)
          if list(out) != expected:
              wrong = [(i, e, g) for i, (e, g) in enumerate(zip(expected, out)) if e != g]
              print(f"@rank.{rank} ReduceScatter/{pattern.__name__} -- FAIL ({len(wrong)} wrong)")
              n = len(wrong) if show_errors is None else show_errors
              for i, e, g in wrong[:n]:
                  print(f"  pos {i}: expected {e} got {g}")
              if n < len(wrong):
                  print(f"  ... and {len(wrong) - n} more")
          else:
            print(f"@rank.{rank} ReduceScatter/{pattern.__name__} -- PASS")

  @staticmethod
  def test_allgather(coll, rank, world, size, show_errors=10):
      for pattern in Test.PATTERNS:
          inp, expected = Test.allgather(pattern, rank, world, size)
          out = [0] * len(expected)
          coll.AllGather(inp, out)
          if list(out) != expected:
              wrong = [(i, e, g) for i, (e, g) in enumerate(zip(expected, out)) if e != g]
              print(f"@rank.{rank} AllGather/{pattern.__name__} -- FAIL ({len(wrong)} wrong)")
              n = len(wrong) if show_errors is None else show_errors
              for i, e, g in wrong[:n]:
                  print(f"  pos {i}: expected {e} got {g}")
              if n < len(wrong):
                  print(f"  ... and {len(wrong) - n} more")
          else:
            print(f"@rank.{rank} AllGather/{pattern.__name__} -- PASS")
