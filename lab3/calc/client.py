from scapy.all import Packet

from util.calculator import Op, Calculator, CalculatorTester

class Calc(Packet):
  # TODO: Define the calculator header
  pass

class MyCalculator(Calculator):
    def exec(self, op : Op, a : int = 0, b : int = 0):
      # TODO: Implement me
      #
      # - Use Scapy to send a Calc packet to the switch to perform
      #   the requested operation
      # - Wait for the switch's response and return it
      #   See util/calculator.py how this function is used
      pass

if __name__ == "__main__":
    c = MyCalculator()
    # Feel free to run operations directly during dev. E.g:
    #
    #   print( c.sub(10, c.add(5, 2)) ) # should print 3
    #
    # In the end however, the following has to pass:
    CalculatorTester().test(c)
    
    
# run with: mx h1 python client.py
