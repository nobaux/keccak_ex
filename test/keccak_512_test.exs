defmodule Keccak512Test do
  use ExUnit.Case

  test "hash_512" do
    hash = "7adf4255f518ca27b9b41ddfd97d4a3799e02347b3b1b7c525b67371b3db350a571b3bddb9732868daeab70f9ac9bd842c8b26e605855899f32f8526c2e6d5ed"
    |> Base.decode16!(case: :mixed)
    |> KeccakEx.hash_512()

    assert hash == <<119, 102, 104, 187, 133, 135, 226, 250, 35, 70, 61, 170, 95, 103, 14, 20, 151,
    254, 102, 171, 158, 87, 43, 121, 196, 107, 148, 120, 126, 133, 100, 218, 10,
    222, 43, 29, 9, 204, 30, 108, 116, 235, 56, 81, 26, 20, 90, 229, 115, 49, 238,
    111, 71, 113, 75, 244, 78, 115, 123, 86, 62, 242, 134, 105>>
  end

  test "hash_512 returns expected hash" do
    data =
      Base.decode64!(
        "5d1Ch4jboo9DcCWGj55ZT/tsW4nnG5+DlCFGddOfjTZmfQdzc4yBnodqszjYIaI+8Io41a789cV5rUwzvqxLzw=="
      )

    hashed_data = KeccakEx.hash_512(data)

    assert <<_::binary-12, address::binary>> = hashed_data

    assert Base.encode16(address, case: :lower) == "a8a7ba9eb805dd98b43914991b80d000c39c6627336e5d415bcbe09d7df0853a4ebafa02ec115f362299ebf009747de0f48c1d12"
  end

  test "returns expected hash 2" do
    data =
      Base.decode64!(
        "77+9eA0U77+977+9H86BZO+/vSIuEV4PAQYzGVjvv73vv73vv73vv70R77+977+977+977+977+977+9Y1k8y7ZA77+9XR/vv71M77+977+9H2ZcW++/ve+/ve+/ve+/ve+/vRvvv71t7pu4NwUYNy8iKVvvv70qNe+/vXDvv73vv73vv71W77+977+9Hxo="
      )

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "f5d74ac8a6cc5cf3d585ac2a27fc134af3bed07161375262252ce0be46970f67c305c269dd5edda69afbb089a398173dea53c916d63e9b77c8fc302c2c0604c1"
  end

  test "returns expected hash 3" do
    data =
      Base.decode64!(
        "FO+/vcybKO+/vRfvv70iUADmk53vv73vv713DEUTf0zvv73vv71rKRnvv70x77+9b++/ve+/ve+/vTrvv70kXgfvv73vv73vv73vv70XTXvvv73vv73vv70M77+9GnNZDu+/ve+/vQDvv73vv71rbkLvv71p77+977+9I8KV77+977+977+977+9f2HRpRwSZHHvv73FmUjvv71CHGoMEe+/vSrvv70A77+977+9d3Dvv73vv73vv70hV++/ve+/ve+/vR9Y77+9IO+/vXnvv71K77+9LC8="
      )

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "9c7acdc6583082fae909421f20ed5fee7e875c82de668cfb5f4c9ae2a4dd15984537a3e56e3bf3aaee38d0ec2fe357e1b170b3e1a51767638e7afed6e1f66fb6"
  end

  test "hash_512 hello" do
    data = "hello"

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39d47de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f976"
  end

  test "hash_512 ascii 1" do
    data = ""

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
  end

  test "hash_512 ascii 2" do
    data = "The quick brown fox jumps over the lazy dog"

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609"
  end

  test "hash_512 ascii 3" do
    data = "The quick brown fox jumps over the lazy dog."

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "ab7192d2b11f51c7dd744e7b3441febf397ca07bf812cceae122ca4ded6387889064f8db9230f173f6d1ab6e24b6e50f065b039f799f5592360a6558eb52d760"
  end

  test "hash_512 ascii more than 128 bytes" do
    data = "The MD5 message-digest algorithm is a widely used cryptographic hash function producing a 128-bit (16-byte) hash value, typically expressed in text format as a 64 digit hexadecimal number. MD5 has been utilized in a wide variety of cryptographic applications, and is also commonly used to verify data integrity."

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "f1df820db659b9a1beb488f74f58e78fadbe8c81a000261a0506708028b97ff11abf0b06168097880df99d5bfbe6460ecf612a2c8559a08142ab1517f6009d1d"
  end

  test "hash_512 UTF-8 a" do
    data = "中文"

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "2f6a1bd50562230229af34b0ccf46b8754b89d23ae2c5bf7840b4acfcef86f87395edc0a00b2bfef53bafebe3b79de2e3e01cbd8169ddbb08bde888dcc893524"
  end

  test "hash_512 UTF-8 b" do
    data = "aécio"

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "c452ec93e83d4795fcab62a76eed0d88f2231a995ce108ac8f130246f87c4a11cb18a2c1a688a5695906a6f863e71bbe8997c6610319ab97f12d2e5bf0afe458"
  end

  test "hash_512 UTF-8 c" do
    data = "𠜎"

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "8a2d72022ce19d989dbe6a0017faccbf5dc2e22c162d1c5eb168864d32dd1a71e1b4782652c148cf6ca47b77a72c96fff682e72bdfef0566d4b7cca3c9ccc59d"
  end

  test "hash_512 UTF-8 more than 128 bytes" do
    data = "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一"

    hashed_data = KeccakEx.hash_512(data)

    assert Base.encode16(hashed_data, case: :lower) == "6a67c28aa1946ca1be8382b861aac4aaf20052f495db9b6902d13adfa603eaba5d169f8896b86d461b2949283eb98e503c3f0640188ea7d6731526fc06568d37"
  end

  test "hash_512 fails to decode number" do
    assert_raise ArgumentError, fn ->
      KeccakEx.hash_512(11)
    end
  end

  test "hash_512 fails to decode nil" do
    assert_raise ArgumentError, fn ->
      KeccakEx.hash_512(nil)
    end
  end

  test "hash_512 fails to decode atom" do
    assert_raise ArgumentError, fn ->
      KeccakEx.hash_512(:atom)
    end
  end

  @tag :perf
  @tag timeout: 300_000
  test "hash_512 sequencial performance test" do
    data = :crypto.strong_rand_bytes(100)

    Benchee.run(
      %{
        "keccak_ex_512_sequencial" => fn ->
          KeccakEx.hash_512(data)
        end
      },
      time: 100,
      memory_time: 100
    )
  end

  @tag :perf
  @tag timeout: 300_000
  test "hash_512 parallel performance test" do
    data = :crypto.strong_rand_bytes(100)

    Benchee.run(
      %{
        "keccak_ex_512_parallel" => fn ->
          KeccakEx.hash_512(data)
        end
      },
      time: 100,
      memory_time: 100,
      parallel: 4
    )
  end
end
