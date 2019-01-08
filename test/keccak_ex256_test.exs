defmodule KeccakEx256Test do
  use ExUnit.Case
  doctest Keccak

  @length 256

  test "hex a..z" do
    {:ok, hash} = Keccak.hash(@length, "a")
    assert hash |> Base.encode16(case: :lower) == "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb"
    {:ok, hash} = Keccak.hash(@length, "b")
    assert hash |> Base.encode16(case: :lower) == "b5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510"
    {:ok, hash} = Keccak.hash(@length, "c")
    assert hash |> Base.encode16(case: :lower) == "0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2"
    {:ok, hash} = Keccak.hash(@length, "d")
    assert hash |> Base.encode16(case: :lower) == "f1918e8562236eb17adc8502332f4c9c82bc14e19bfc0aa10ab674ff75b3d2f3"
    {:ok, hash} = Keccak.hash(@length, "e")
    assert hash |> Base.encode16(case: :lower) == "a8982c89d80987fb9a510e25981ee9170206be21af3c8e0eb312ef1d3382e761"
    {:ok, hash} = Keccak.hash(@length, "f")
    assert hash |> Base.encode16(case: :lower) == "d1e8aeb79500496ef3dc2e57ba746a8315d048b7a664a2bf948db4fa91960483"
    {:ok, hash} = Keccak.hash(@length, "g")
    assert hash |> Base.encode16(case: :lower) == "14bcc435f49d130d189737f9762feb25c44ef5b886bef833e31a702af6be4748"
    {:ok, hash} = Keccak.hash(@length, "h")
    assert hash |> Base.encode16(case: :lower) == "a766932420cc6e9072394bef2c036ad8972c44696fee29397bd5e2c06001f615"
    {:ok, hash} = Keccak.hash(@length, "i")
    assert hash |> Base.encode16(case: :lower) == "ea00237ef11bd9615a3b6d2629f2c6259d67b19bb94947a1bd739bae3415141c"
    {:ok, hash} = Keccak.hash(@length, "j")
    assert hash |> Base.encode16(case: :lower) == "b31d742db54d6961c6b346af2c9c4c495eb8aff2ebf6b3699e052d1cef5cf50b"
    {:ok, hash} = Keccak.hash(@length, "k")
    assert hash |> Base.encode16(case: :lower) == "f3d0adcb6a1c70832365e9da0a6b2f5199422f6a53c67cfad171114e3442aa0f"
    {:ok, hash} = Keccak.hash(@length, "l")
    assert hash |> Base.encode16(case: :lower) == "6a0d259bd4fb907339fd7c65a133083c1e9554f2ca6325b806612c8df6d7df22"
    {:ok, hash} = Keccak.hash(@length, "m")
    assert hash |> Base.encode16(case: :lower) == "daba8c984363447d18bf8210079973ac8fc1ce76864315b5baacf246bf6e72f6"
    {:ok, hash} = Keccak.hash(@length, "n")
    assert hash |> Base.encode16(case: :lower) == "4b4ecedb4964a40fe416b16c7bd8b46092040ec42ef0aa69e59f09872f105cf3"
    {:ok, hash} = Keccak.hash(@length, "o")
    assert hash |> Base.encode16(case: :lower) == "53a63b3ee437e1aa804722ac8f2f57053ac47e1bb887f095340cf5990e7faad3"
    {:ok, hash} = Keccak.hash(@length, "p")
    assert hash |> Base.encode16(case: :lower) == "2304e88f144ae9318c71b0fb9e0f44bd9e0c6c58fb1b5315a35fd8b4b2a444ab"
    {:ok, hash} = Keccak.hash(@length, "q")
    assert hash |> Base.encode16(case: :lower) == "3ff269d37634c240a40e1b0de0d61faffb6bbb3c251727e2ef176a979d8b95ff"
    {:ok, hash} = Keccak.hash(@length, "r")
    assert hash |> Base.encode16(case: :lower) == "414f72a4d550cad29f17d9d99a4af64b3776ec5538cd440cef0f03fef2e9e010"
    {:ok, hash} = Keccak.hash(@length, "s")
    assert hash |> Base.encode16(case: :lower) == "60a73bfb121a98fb6b52dfb29eb0defd76b60065b8cf07902baf28c167d24daf"
    {:ok, hash} = Keccak.hash(@length, "t")
    assert hash |> Base.encode16(case: :lower) == "cac1bb71f0a97c8ac94ca9546b43178a9ad254c7b757ac07433aa6df35cd8089"
    {:ok, hash} = Keccak.hash(@length, "u")
    assert hash |> Base.encode16(case: :lower) == "32cefdcd8e794145c9af8dd1f4b1fbd92d6e547ae855553080fc8bd19c4883a0"
    {:ok, hash} = Keccak.hash(@length, "v")
    assert hash |> Base.encode16(case: :lower) == "a147871e98dd2eddde100a3ea8cc6316a0d516adb61013ba565a9cd96e86f510"
    {:ok, hash} = Keccak.hash(@length, "w")
    assert hash |> Base.encode16(case: :lower) == "01544badb249bb61e3fa1c5ce16e082fa1344cdee4a7389bf5502178c1892d4e"
    {:ok, hash} = Keccak.hash(@length, "x")
    assert hash |> Base.encode16(case: :lower) == "7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83"
    {:ok, hash} = Keccak.hash(@length, "y")
    assert hash |> Base.encode16(case: :lower) == "83847cf31c36389df832d0d4d3df7cf28f211e3f83173e5c157bab31573d61f3"
    {:ok, hash} = Keccak.hash(@length, "z")
    assert hash |> Base.encode16(case: :lower) == "41e406698d040bb44cf693b3dc50c37cf3c854c422d2645b1101662741fbaa88"
  end

  test "hex A..Z" do
    {:ok, hash} = Keccak.hash(@length, "A")
    assert hash |> Base.encode16(case: :lower) == "03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760"
    {:ok, hash} = Keccak.hash(@length, "B")
    assert hash |> Base.encode16(case: :lower) == "1f675bff07515f5df96737194ea945c36c41e7b4fcef307b7cd4d0e602a69111"
    {:ok, hash} = Keccak.hash(@length, "C")
    assert hash |> Base.encode16(case: :lower) == "017e667f4b8c174291d1543c466717566e206df1bfd6f30271055ddafdb18f72"
    {:ok, hash} = Keccak.hash(@length, "D")
    assert hash |> Base.encode16(case: :lower) == "6c3fd336b49dcb1c57dd4fbeaf5f898320b0da06a5ef64e798c6497600bb79f2"
    {:ok, hash} = Keccak.hash(@length, "E")
    assert hash |> Base.encode16(case: :lower) == "434b529473163ef4ed9c9341d9b7250ab9183c27e7add004c3bba38c56274e24"
    {:ok, hash} = Keccak.hash(@length, "F")
    assert hash |> Base.encode16(case: :lower) == "e61d9a3d3848fb2cdd9a2ab61e2f21a10ea431275aed628a0557f9dee697c37a"
    {:ok, hash} = Keccak.hash(@length, "G")
    assert hash |> Base.encode16(case: :lower) == "077da99d806abd13c9f15ece5398525119d11e11e9836b2ee7d23f6159ad87d2"
    {:ok, hash} = Keccak.hash(@length, "H")
    assert hash |> Base.encode16(case: :lower) == "321c2cb0b0673952956a3bfa56cf1ce4df0cd3371ad51a2c5524561250b01836"
    {:ok, hash} = Keccak.hash(@length, "I")
    assert hash |> Base.encode16(case: :lower) == "8d61ecf6e15472e15b1a0f63cd77f62aa57e6edcd3871d7a841f1056fb42b216"
    {:ok, hash} = Keccak.hash(@length, "J")
    assert hash |> Base.encode16(case: :lower) == "90174c907fea3d27ea14230ef6800c7bde0f907fb10d2c747a17af161f784d19"
    {:ok, hash} = Keccak.hash(@length, "K")
    assert hash |> Base.encode16(case: :lower) == "91cb023ee03dcff3e185aa303e77c329b6b62e0a68a590039a476bc8cb48d055"
    {:ok, hash} = Keccak.hash(@length, "L")
    assert hash |> Base.encode16(case: :lower) == "8aa64f937099b65a4febc243a5ae0f2d6416bb9e473c30dd29c1ee498fb7c5a8"
    {:ok, hash} = Keccak.hash(@length, "M")
    assert hash |> Base.encode16(case: :lower) == "7d61fdc86cb928ea48fbf22d28ed5341c2e6a2599c550270b824b71dfa078d06"
    {:ok, hash} = Keccak.hash(@length, "N")
    assert hash |> Base.encode16(case: :lower) == "7c1e3133c5e040bb7fc55cda56e3c1998a2e33373c0850e92b53c932b65ceb44"
    {:ok, hash} = Keccak.hash(@length, "O")
    assert hash |> Base.encode16(case: :lower) == "c669aa98d5975cc43653c879a18d9bc4aa8bf51e69f61aeb1d7769216f98009a"
    {:ok, hash} = Keccak.hash(@length, "P")
    assert hash |> Base.encode16(case: :lower) == "7b2ab94bb7d45041581aa3757ae020084674ccad6f75dc3750eb2ea8a92c4e9a"
    {:ok, hash} = Keccak.hash(@length, "Q")
    assert hash |> Base.encode16(case: :lower) == "fbf3cc6079e09a6a2a778706898aef91b633ff613801d212e0afe7f411ddb1d2"
    {:ok, hash} = Keccak.hash(@length, "R")
    assert hash |> Base.encode16(case: :lower) == "ef22bddd350b943170a67d35191c27e310709a28c38b5762a152ff640108f5b2"
    {:ok, hash} = Keccak.hash(@length, "S")
    assert hash |> Base.encode16(case: :lower) == "a9463b19d1148abedba3d6925530d4465b271ce2cc61f80b1a0a80fd73eab881"
    {:ok, hash} = Keccak.hash(@length, "T")
    assert hash |> Base.encode16(case: :lower) == "846b7b6deb1cfa110d0ea7ec6162a7123b761785528db70cceed5143183b11fc"
    {:ok, hash} = Keccak.hash(@length, "U")
    assert hash |> Base.encode16(case: :lower) == "37bf2238b11b68cdc8382cece82651b59d3c3988873b6e0f33d79694aa45f1be"
    {:ok, hash} = Keccak.hash(@length, "V")
    assert hash |> Base.encode16(case: :lower) == "f0da850a6b7c61a66cdd43ac7529affc6000442af1c1bdda1db3bb7220bf7613"
    {:ok, hash} = Keccak.hash(@length, "W")
    assert hash |> Base.encode16(case: :lower) == "d2ec75cd002cc54c4cc6690500ee64d030751a1b19466a4ba8be1b42eb5a1031"
    {:ok, hash} = Keccak.hash(@length, "X")
    assert hash |> Base.encode16(case: :lower) == "550c64a15031c3064454c19adc6243a6122c138a242eaa098da50bb114fc8d56"
    {:ok, hash} = Keccak.hash(@length, "Y")
    assert hash |> Base.encode16(case: :lower) == "9a2c5f9025f1f0333863704310875ae81a574171bed5b047cfc0f50e347f630e"
    {:ok, hash} = Keccak.hash(@length, "Z")
    assert hash |> Base.encode16(case: :lower) == "7d54a4ab605dc825939ee59b4af5be4680f51892ef5944365e996fd93f70a2e5"
  end

  test "hash hello world" do
    {:ok, hash} = Keccak.hash(@length, "hello world")
    assert hash == <<71, 23, 50, 133, 168, 215, 52, 30, 94, 151, 47, 198, 119, 40, 99,
             132, 248, 2, 248, 239, 66, 165, 236, 95, 3, 187, 250, 37, 76, 176,
             31, 173>>
  end

  test "hash! hello world" do
    hash = Keccak.hash!(@length, "hello world")
    assert hash == <<71, 23, 50, 133, 168, 215, 52, 30, 94, 151, 47, 198, 119, 40, 99,
             132, 248, 2, 248, 239, 66, 165, 236, 95, 3, 187, 250, 37, 76, 176,
             31, 173>>
  end
end