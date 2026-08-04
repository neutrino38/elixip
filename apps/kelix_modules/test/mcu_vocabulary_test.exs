defmodule Kelix.Mod.Mcu.VocabularyTest do
  @moduledoc """
  The human names of the MCU's wire enums (design `docs/design/mcu_module.md` §8.3.7):
  one table, read for the CLI labels, for the accepted input, for the config block and
  for the online help.

  The short `layout` form is what most of this covers — it is the one place where a
  *syntax* is read, and the one place an operator can get it wrong.
  """
  use ExUnit.Case, async: true

  alias Kelix.Mod.Mcu.Vocabulary

  describe "one value, by name or by id" do
    test "a name resolves to the wire id, case-insensitively" do
      assert {:ok, 1} = Vocabulary.comp("2x2")
      assert {:ok, 9} = Vocabulary.comp("4x4")
      assert {:ok, 7} = Vocabulary.comp("PIP1")
      assert {:ok, 2} = Vocabulary.size("vga")
      assert {:ok, 6} = Vocabulary.size("HD720p")
      assert {:ok, 2} = Vocabulary.vad("full")
    end

    test "the wire id still passes, quoted or not — a REST client may send either" do
      assert {:ok, 6} = Vocabulary.size(6)
      assert {:ok, 6} = Vocabulary.size("6")
      assert {:ok, 0} = Vocabulary.vad(0)
    end

    test "`720p` is the one alias, because that is what a video stack calls it" do
      assert {:ok, 6} = Vocabulary.size("720p")
    end

    test "nil passes through, so an absent argument needs no special case" do
      assert {:ok, nil} = Vocabulary.comp(nil)
      assert {:ok, nil} = Vocabulary.vad(nil)
    end

    test "an unknown name answers with the vocabulary, under the caller's own key" do
      assert {:error, msg} = Vocabulary.comp("2+2", "layout.comp")
      assert msg =~ ~s(layout.comp: unknown mosaic "2+2")
      assert msg =~ "one of 1x1, 2x2, 3x3, 3+4, 1+7, 1+5, 1+1, pip1, pip3, 4x4, 1+4, 2+8"

      assert {:error, msg} = Vocabulary.size("4k", "video_size")
      assert msg =~ ~s(video_size: unknown video size "4k")
      assert msg =~ "qcif, cif, vga"
    end

    test "an id no enum holds is refused too — 12 is not a mosaic" do
      assert {:error, msg} = Vocabulary.comp(12, "layout_comp")
      assert msg =~ "layout_comp: 12 is not a mosaic id"
      assert {:error, msg} = Vocabulary.size(8)
      assert msg =~ "8 is not a video size id"
    end
  end

  describe "the short layout form" do
    test "a mosaic and a size, in either order, spaces or commas" do
      assert {:ok, %{"comp" => 1, "size" => 6, "auto" => false}} = Vocabulary.layout("2x2 hd720p")
      assert {:ok, %{"comp" => 1, "size" => 6, "auto" => false}} = Vocabulary.layout("hd720p 2x2")
      assert {:ok, %{"comp" => 1, "size" => 6, "auto" => false}} = Vocabulary.layout("2x2,hd720p")

      assert {:ok, %{"comp" => 1, "size" => 6, "auto" => false}} =
               Vocabulary.layout(" 2x2 , 720p ")
    end

    test "only what is named travels: the merge of §8.3.3 keeps the rest" do
      assert {:ok, %{"size" => 1}} = Vocabulary.layout("cif")
      assert {:ok, %{"auto" => true}} = Vocabulary.layout("auto")
      assert {:ok, %{"auto" => false}} = Vocabulary.layout("manual")
      # a size alone must not touch the mosaic — nor its auto flag
      refute Map.has_key?(elem(Vocabulary.layout("cif"), 1), "auto")
    end

    test "naming a mosaic implies manual, or the next arrival would undo it" do
      assert {:ok, %{"comp" => 6, "auto" => false}} = Vocabulary.layout("1+1")
    end

    test "…unless auto is given in the same value, which then wins" do
      assert {:ok, %{"comp" => 1, "size" => 2, "auto" => true}} =
               Vocabulary.layout("auto 2x2 vga")
    end

    test "case and mixed vocabularies are fine" do
      assert {:ok, %{"comp" => 8, "size" => 15, "auto" => true}} =
               Vocabulary.layout("AUTO PIP3 WVGA")
    end

    test "an unknown token names itself and prints the syntax" do
      assert {:error, msg} = Vocabulary.layout("2+2 vga")
      assert msg =~ ~s(layout: unknown "2+2")
      # the vocabulary comes with the refusal, where it is needed
      assert msg =~ "mosaics: 1x1 2x2 3x3 3+4 1+7 1+5 1+1 pip1 pip3 4x4 1+4 2+8"
      assert msg =~ "sizes: qcif cif vga pal hvga qvga hd720p wqvga xga wvga"
      assert msg =~ "modes: auto manual"
    end

    test "two tokens of the same group is a refusal, not a last-one-wins" do
      assert {:error, msg} = Vocabulary.layout("2x2 3x3")
      assert msg =~ ~s("2x2" and "3x3" both set the mosaic)

      assert {:error, msg} = Vocabulary.layout("vga cif")
      assert msg =~ "both set the size"

      assert {:error, msg} = Vocabulary.layout("auto manual")
      assert msg =~ "both set the mode"
    end

    test "a bare number is ambiguous and says so, with both ways out" do
      assert {:error, msg} = Vocabulary.layout(6)
      assert msg =~ "6 alone is ambiguous"
      assert msg =~ "2x2 hd720p"
      assert msg =~ ~s({"comp":6})
    end

    test "an empty value is a refusal" do
      assert {:error, msg} = Vocabulary.layout("   ")
      assert msg =~ "layout: nothing given"
    end
  end

  describe "the wire layout form" do
    test "names are accepted inside it, and become ids" do
      assert {:ok, %{"comp" => 2, "size" => 2}} =
               Vocabulary.layout(%{"comp" => "3x3", "size" => "vga"})
    end

    test "it stays literal: no implied manual, so a PUT body means what it says" do
      assert {:ok, decoded} = Vocabulary.layout(%{"comp" => 9})
      refute Map.has_key?(decoded, "auto")
    end

    test "the atom-keyed table a scenario writes is the same reading (§17.2)" do
      assert {:ok, %{"comp" => 6, "auto" => true}} = Vocabulary.layout(%{comp: "1+1", auto: true})
    end

    test "an unknown field is left for Args.sub_map to name — not dropped here" do
      assert {:ok, %{"rows" => 2}} = Vocabulary.layout(%{"rows" => 2})
    end

    test "a bad name inside it is reported under its dotted path" do
      assert {:error, msg} = Vocabulary.layout(%{"size" => "4k"})
      assert msg =~ "layout.size: unknown video size"
    end
  end

  describe "video/2" do
    test "size takes a name; the other fields are untouched" do
      assert {:ok, %{"size" => 2, "fps" => 25}} =
               Vocabulary.video(%{"size" => "vga", "fps" => 25})
    end

    test "a profile without a size passes through" do
      assert {:ok, %{"fps" => 25}} = Vocabulary.video(%{fps: 25})
    end

    test "a bad size is reported under video.size" do
      assert {:error, msg} = Vocabulary.video(%{"size" => "svga"})
      assert msg =~ "video.size: unknown video size"
    end
  end

  describe "the tables the rest of the module reads" do
    test "the CLI labels are the reverse of what the parser accepts" do
      assert Vocabulary.mosaic_names()["1"] == "2x2"
      assert Vocabulary.size_names()["6"] == "hd720p"
      assert Vocabulary.vad_names()["2"] == "full"

      # …and every label round-trips to the id it was rendered from
      for {id, name} <- Vocabulary.mosaic_names() do
        assert {:ok, back} = Vocabulary.comp(name)
        assert Integer.to_string(back) == id
      end
    end

    test "the help prints the vocabulary the parser enforces" do
      help = Enum.join(Vocabulary.layout_help(), "\n")

      for name <- Vocabulary.mosaics(), do: assert(help =~ name)
      for name <- Vocabulary.sizes(), do: assert(help =~ name)
      assert help =~ "auto"
      assert help =~ "manual"
      assert Enum.join(Vocabulary.vad_help(), " ") =~ "none | basic | full"
    end
  end
end
