import argparse
from util.collectives import Collectives, Test
from util.network import get_ip, set_drop_prob, recv, send

class MyCollectives(Collectives):
    def __init__(self, rank, world):
        self.rank = rank
        self.world = world

    def AllReduce(self, input: list[int], output: list[int], op : str = "sum"):
        assert len(input), "input cannot be empty"
        assert len(input) == len(output), "input and output must have the same size"
        # TODO: Implement me. Ignore the op argument unless you are attempting the bonus

    def ReduceScatter(self, input: list[int], output: list[int]):
        assert len(input), "input cannot be empty"
        assert len(input) == (len(output) * self.world), "input size must be N * output size"
        # TODO: Implement me only if you attempt the bonus

    def AllGather(self, input: list[int], output: list[int]):
        assert len(input), "input cannot be empty"
        assert len(output) == (len(input) * self.world), "input size must be N * input size"
        # TODO: Implement me only if you attempt the bonus


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("rank", type=int)
    p.add_argument("world", type=int)
    args = p.parse_args()

    coll = Collectives(args.rank, args.world)

    # TODO: Run more tests, do not rely only on the following

    data, expected = Test.data.ar_iota_rot(args.rank, args.world, 66)

    coll.AllReduce(data, data)

    print(f"expected({len(expected)}): {expected}")
    print(f"  actual({len(data)}): {data}")
