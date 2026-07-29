defmodule Kelix.DialPlanTest do
  use ExUnit.Case, async: true

  import Kelix.DialPlan, only: [matches?: 2]

  describe "digit classes X / Z / N" do
    test "X matches any digit, whole string" do
      assert matches?("XXXX", "1234")
      assert matches?("XXXX", "0000")
      refute matches?("XXXX", "123")
      refute matches?("XXXX", "12345")
      refute matches?("XXXX", "12a4")
    end

    test "Z is 1-9, N is 2-9" do
      assert matches?("Z", "1")
      assert matches?("Z", "9")
      refute matches?("Z", "0")
      assert matches?("N", "2")
      refute matches?("N", "1")
      refute matches?("N", "0")
    end
  end

  describe "literals" do
    test "literal digits match exactly" do
      assert matches?("888", "888")
      refute matches?("888", "88")
      refute matches?("888", "8888")
      refute matches?("888", "889")
    end

    test "mixed literal + classes (national number example)" do
      # 0[1-9]XXXXXXXX  -> 0, then 1-9, then 8 digits = 10 chars
      assert matches?("0[1-9]XXXXXXXX", "0612345678")
      refute matches?("0[1-9]XXXXXXXX", "0012345678")  # second char must be 1-9
      refute matches?("0[1-9]XXXXXXXX", "061234567")   # too short
    end
  end

  describe "[...] sets and ranges" do
    test "simple range" do
      assert matches?("[1-9]", "5")
      refute matches?("[1-9]", "0")
    end

    test "mixed char + range: [13-6] = {1,3,4,5,6}" do
      for c <- ["1", "3", "4", "5", "6"], do: assert(matches?("[13-6]", c))
      for c <- ["0", "2", "7", "9"], do: refute(matches?("[13-6]", c))
    end
  end

  describe "wildcards . and !" do
    test ". matches one or more chars" do
      assert matches?("9.", "91")
      assert matches?("9.", "9123456")
      refute matches?("9.", "9")     # needs at least one more
      refute matches?("9.", "8123")
    end

    test "! matches zero or more chars" do
      assert matches?("9!", "9")
      assert matches?("9!", "9123")
      refute matches?("9!", "8")
    end

    test "wildcard followed by a literal (backtracking)" do
      assert matches?("0.9", "0119")
      assert matches?("0.9", "0X9")
      refute matches?("0.9", "09")   # `.` needs >=1 between 0 and 9
    end
  end

  describe "compile/1 errors" do
    test "unterminated set" do
      assert {:error, :unterminated_set} = Kelix.DialPlan.compile("[1-9")
    end

    test "empty set" do
      assert {:error, :empty_set} = Kelix.DialPlan.compile("[]")
    end

    test "stray closing bracket" do
      assert {:error, :unexpected_closing_bracket} = Kelix.DialPlan.compile("1]")
    end

    test "a valid pattern compiles to a usable matcher" do
      assert {:ok, m} = Kelix.DialPlan.compile("XXXX")
      assert m.("1234")
    end
  end
end
