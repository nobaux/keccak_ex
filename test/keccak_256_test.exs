defmodule Keccak256Test do
  use ExUnit.Case

  test "hash_256" do
    hash = "7adf4255f518ca27b9b41ddfd97d4a3799e02347b3b1b7c525b67371b3db350a571b3bddb9732868daeab70f9ac9bd842c8b26e605855899f32f8526c2e6d5ed"
    |> Base.decode16!(case: :mixed)
    |> KeccakEx.hash_256()

    assert hash == <<170, 68, 45, 42, 41, 217, 15, 232, 186, 206, 34, 243, 192, 82,
             108, 106, 223, 154, 173, 171, 167, 80, 45, 69, 65, 191, 240, 51,
             185, 140, 72, 181>>
  end

  test "returns expected hash" do
    data =
      Base.decode64!(
        "5d1Ch4jboo9DcCWGj55ZT/tsW4nnG5+DlCFGddOfjTZmfQdzc4yBnodqszjYIaI+8Io41a789cV5rUwzvqxLzw=="
      )

    hashed_data = KeccakEx.hash_256(data)

    assert <<_::binary-12, address::binary-20>> = hashed_data

    assert Base.encode16(address, case: :lower) == "73bb50c828fd325c011d740fde78d02528826156"
  end

  test "returns expected hash 2" do
    data =
      Base.decode64!(
        "NRFFf++/vTdsF3Zybg8P77+977+9Mu+/vTHvv73vv70t77+9YO+/ve+/ve+/vWDvv71mBmxFWe+/ve+/ve+/ve+/vUTvv70KaO+/ve+/ve+/vU3vv71/77+977+9Be+/ve+/vXfvv73vv73vv71177+9Iu+/ve+/vXtsa++/vR5p77+9cu+/vRpxzoDvv71O77+977+9bX0PKV94ZVYQRAzvv704Ae+/ve+/ve+/vT90IO+/ve+/ve+/ve+/ve+/vSDvv73vv71T77+9CWDvv70bd++/vWrvv70r77+9Je+/vWXvv70FTe+/ve+/vVHvv71CcG3vv70877+9MnDvv73vv71Tenvvv701au+/vQ=="
      )

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "448773b97c6ba19b01af1950c1d272bc660188eaea57c8a9a7b7e97e8f8d09cc"
  end

  test "returns expected hash 3" do
    data =
      Base.decode64!(
        "KEjVmd+5Ue+/vTNTWSjvv73vv73cmu+/vVHvv71CCu+/vT/vv73vv70VNQDvv70oPu+/vT3vv73vv73vv73vv70877+9UUFn77+9UntM3LHvv73vv73vv73vv73ZnBDvv73vv73NmO+/ve+/ve+/vUjvv73vv73vv73vv73Qnu+/ve+/vSTvv71777+977+977+96K2OO++/vW8V77+977+9Yu+/ve+/vXDvv73vv73vv73vv71177+977+9Qu+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/vRc177+9YT/vv73vv70TK++/ve+/vQc377+9EFFrPh4Of++/vSTvv70s77+977+9E37vv73vv73vv70NNnTvv73vv73vv73vv71J77+9Oe+/vVdM77+977+977+9TNO7aO+/vUdBRu+/ve+/vU0F77+977+91KXvv73vv71TAHPvv73vv73Gv++/vTvvv71IeDUN77+9GBEJPu+/vXM2Te+/ve+/vSA4Te+/ve+/vUTEpG3vv700KiPvv73vv73vv70="
      )

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "99e22c8d749ab49cf7c95e6aeb097a0cc59f34fad41c65ff172f54a521e93f1a"
  end

  test "hash hello" do
    data = "hello"

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
  end

  test "hash ascii 1" do
    data = ""

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
  end

  test "hash ascii 2" do
    data = "The quick brown fox jumps over the lazy dog"

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
  end

  test "hash ascii 3" do
    data = "The quick brown fox jumps over the lazy dog."

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d"
  end

  test "hash ascii more than 128 bytes" do
    data = "The MD5 message-digest algorithm is a widely used cryptographic hash function producing a 128-bit (16-byte) hash value, typically expressed in text format as a 32 digit hexadecimal number. MD5 has been utilized in a wide variety of cryptographic applications, and is also commonly used to verify data integrity."

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "af20018353ffb50d507f1555580f5272eca7fdab4f8295db4b1a9ad832c93f6d"
  end

  test "hash UTF-8 a" do
    data = "中文"

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "70a2b6579047f0a977fcb5e9120a4e07067bea9abb6916fbc2d13ffb9a4e4eee"
  end

  test "hash UTF-8 b" do
    data = "aécio"

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "d7d569202f04daf90432810d6163112b2695d7820da979327ebd894efb0276dc"
  end

  test "hash UTF-8 c" do
    data = "𠜎"

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "16a7cc7a58444cbf7e939611910ddc82e7cba65a99d3e8e08cfcda53180a2180"
  end

  test "hash UTF-8 more than 128 bytes" do
    data = "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一"

    hashed_data = KeccakEx.hash_256(data)

    assert Base.encode16(hashed_data, case: :lower) == "d1021d2d4c5c7e88098c40f422af68493b4b64c913cbd68220bf5e6127c37a88"
  end

  test "fails to decode number" do
    assert_raise ArgumentError, fn ->
      KeccakEx.hash_256(11)
    end
  end

  test "fails to decode nil" do
    assert_raise ArgumentError, fn ->
      KeccakEx.hash_256(nil)
    end
  end

  test "fails to decode atom" do
    assert_raise ArgumentError, fn ->
      KeccakEx.hash_256(:atom)
    end
  end

  @tag :perf
  @tag timeout: 300_000
  test "sequencial performance test" do
    data = :crypto.strong_rand_bytes(100)

    Benchee.run(
      %{
        "keccak_ex_256_sequencial" => fn ->
          KeccakEx.hash_256(data)
        end
      },
      time: 100,
      memory_time: 100
    )
  end

  @tag :perf
  @tag timeout: 300_000
  test "parallel performance test" do
    data = :crypto.strong_rand_bytes(100)

    Benchee.run(
      %{
        "keccak_ex_256_parallel" => fn ->
          KeccakEx.hash_256(data)
        end
      },
      time: 100,
      memory_time: 100,
      parallel: 4
    )
  end
end
