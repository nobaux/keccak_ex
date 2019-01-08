defmodule Keccak do
  @moduledoc """
  Implementation of Keccak in pure Elixir.

  NO OPTIMIZED!!!
  """
  use Bitwise

  @keccak_round_constants [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
  ]

  defstruct state: nil,
            data_queue: nil,
            rate: 0,
            rate_bytes: 0,
            bytes_in_queue: 0,
            bits_in_queue: 0,
            fixed_output_length: 0,
            offset: 0,
            length: 0,
            data: nil,
            full: 0,
            partial: 0,
            hash: nil

  @doc """
  Returns the keccak hash.

  ## Examples
      iex> {:ok, hash} = Keccak.hash(256, "hello world")
      iex> hash
      <<71, 23, 50, 133, 168, 215, 52, 30, 94, 151, 47, 198, 119, 40, 99,
             132, 248, 2, 248, 239, 66, 165, 236, 95, 3, 187, 250, 37, 76, 176,
             31, 173>>
  """
  def hash(bit_length, value) do
    rate = 1600 - (bit_length <<< 1)
    length = String.length(value)

    %Keccak{hash: hash} = %Keccak{
      state: List.duplicate(0, 25),
      data_queue: List.duplicate(0, 192),
      rate: rate,
      fixed_output_length: (1600 - rate) >>> 1,
      length: length,
      data: value <> <<0>> |> Binary.to_list() |> Enum.take(length)
    }
    |> absorb()
    |> squeeze()

    {:ok, hash}
  end

  @doc """
  Returns the keccak hash.

  ## Examples
      iex> Keccak.hash!(256, "hello world")
      <<71, 23, 50, 133, 168, 215, 52, 30, 94, 151, 47, 198, 119, 40, 99,
             132, 248, 2, 248, 239, 66, 165, 236, 95, 3, 187, 250, 37, 76, 176,
             31, 173>>
  """
  def hash!(bit_length, value) do
    {:ok, hash} = hash(bit_length, value)
    hash
  end

  defp absorb(%Keccak{rate: rate, bits_in_queue: bits_in_queue} = hashing) do
    rate_bytes = rate >>> 3
    bytes_in_queue = bits_in_queue >>> 3
    %{hashing | rate_bytes: rate_bytes, bits_in_queue: bytes_in_queue}
    |> absorb_loop(0)
    |> set_bits_in_queue()
  end

  defp set_bits_in_queue(%Keccak{bytes_in_queue: bytes_in_queue} = hashing) do
    %{hashing | bits_in_queue: bytes_in_queue <<< 3}
  end

  defp set_bits_in_queue(%Keccak{} = hashing, value) do
    %{hashing | bits_in_queue: value}
  end

  defp absorb_loop(%Keccak{bytes_in_queue: bytes_in_queue, length: length, rate_bytes: rate_bytes} = _hashing, count)
    when bytes_in_queue == 0 and count <= (length - rate_bytes) do
    # IO.inspect("nothing from now...")
    raise "No idea..."
  end

  defp absorb_loop(%Keccak{length: length} = hashing, count) when count < length do
    %Keccak{
      bytes_in_queue: bytes_in_queue, 
      rate_bytes: rate_bytes,
      data_queue: data_queue,
      data: data,
      offset: offset
    } = hashing

    partial_block = min(rate_bytes - bytes_in_queue, length - count)
    copied = copy(data, offset + count, data_queue, bytes_in_queue, partial_block)

    hashing
    |> set_data_queue(copied)
    |> set_bytes_in_queue(bytes_in_queue + partial_block)
    |> keccak_absorb_path() # when bytes_in_queue == rate_bytes
    |> absorb_loop(count + partial_block)
  end

  defp absorb_loop(%Keccak{} = hashing, _count) do
    hashing
  end

  defp set_bytes_in_queue(%Keccak{} = hashing, bytes_in_queue) do
    %{hashing | bytes_in_queue: bytes_in_queue}
  end

  defp set_data_queue(%Keccak{} = hashing, data_queue) do
    %{hashing | data_queue: data_queue}
  end

  defp copy(source, source_index, destination, destination_index, length) do
    data = source
    |> Enum.take(-length(source) + source_index)
    |> Enum.take(length)

    start = destination
    |> Enum.take(destination_index)

    final = destination
    |> Enum.take(-length(destination) + destination_index + length)

    start ++ data ++ final
  end

  defp keccak_absorb_path(%Keccak{bytes_in_queue: bytes_in_queue, rate_bytes: rate_bytes} = hashing) do
    if bytes_in_queue == rate_bytes do
      hashing
      |> keccak_absorb()
      |> set_bytes_in_queue(0)
    else
      hashing
    end
  end

  defp keccak_absorb(%Keccak{} = hashing) do
     hashing
  end

  defp le_to_uint64(data, off) do
    lo = le_to_uint32(data, off)
    hi = le_to_uint32(data, off + 4)

    hi <<< 32 ||| lo
  end

  defp le_to_uint32(data, off) do
    v1 = Enum.at(data, off)
    v2 = Enum.at(data, off + 1) <<< 8
    v3 = Enum.at(data, off + 2) <<< 16
    v4 = Enum.at(data, off + 3) <<< 24

    v1 ||| v2 ||| v3 ||| v4
  end

  defp partial_squeeze(%Keccak{bits_in_queue: bits_in_queue, full: full, data_queue: data_queue, state: state, offset: offset} = hashing) do
    partial = bits_in_queue &&& 63
    if partial > 0 do
      mask = (1 <<< partial) - 1

      value = Enum.at(state, full)
      fixed = value ^^^ le_to_uint64(data_queue, offset) &&& mask
      replaced = List.replace_at(state, full, fixed)

      %{hashing | state: replaced}
    else
      hashing
    end
  end

  defp full_squeeze(%Keccak{bits_in_queue: bits_in_queue} = hashing) do
    full = bits_in_queue >>> 6
    data_state = hashing
    |> keccak_absorb_for(0, full)
    %{data_state | full: full}
  end

  defp keccak_absorb_for(%Keccak{} = hashing, index, to) when index < to do
    %Keccak{
      # bytes_in_queue: bytes_in_queue,
      data_queue: data_queue,
      state: state,
      offset: offset
    } = hashing

    value = Enum.at(state, index)
    fixed = value ^^^ le_to_uint64(data_queue, offset)
    replaced = List.replace_at(state, index, fixed)

    %{hashing | offset: offset + 8, state: replaced}
    |> keccak_absorb_for(index + 1, to)
  end

  defp keccak_absorb_for(%Keccak{} = hashing, index, to) when index < to do
    %Keccak{
      #bytes_in_queue: bytes_in_queue,
      data_queue: data_queue,
      state: state,
      offset: offset
    } = hashing

    value = Enum.at(state, index)
    fixed = value ^^^ le_to_uint64(data_queue, offset)
    replaced = List.replace_at(state, index, fixed)

    keccak_absorb_for(index + 1, to, %{hashing | offset: offset + 8, state: replaced})
  end

  defp keccak_absorb_for(%Keccak{} = hashing, _index, _to) do
    hashing
  end

  defp squeeze(%Keccak{} = hashing) do
    hashing
    |> pad_and_switch_to_squeezing_phase()
    |> squeeze_loop(0, 0)
  end

  defp squeeze_loop(%Keccak{fixed_output_length: fixed_output_length, bits_in_queue: bits_in_queue, rate: rate} = hashing, offset, index)
      when index < fixed_output_length and bits_in_queue == 0 do
    hashing
    |> keccak_permutation()
    |> keccak_extract()
    |> set_bits_in_queue(rate)
    |> squeeze_loop(offset, index)
  end

  defp squeeze_loop(%Keccak{fixed_output_length: fixed_output_length} = hashing, offset, index)
      when index < fixed_output_length do
    %Keccak{
      data_queue: data_queue,
      bits_in_queue: bits_in_queue,
      rate: rate
    } = hashing

    partial_block = min(bits_in_queue, fixed_output_length - index)

    data = copy(data_queue, (rate - bits_in_queue) >>> 3, List.duplicate(0, rate >>> 3), offset + (index >>> 3), partial_block >>> 3)

    %{hashing | data_queue: data, bits_in_queue: bits_in_queue - partial_block}
    |> squeeze_loop(offset, index + partial_block)
  end

  defp squeeze_loop(%Keccak{data_queue: data_queue} = hashing, _offset, _index) do
    hash =
      data_queue
      |> Binary.from_list()
      |> Binary.trim_trailing()

    %{hashing | hash: hash}
  end

  defp pad_and_switch_to_squeezing_phase_path(%Keccak{bits_in_queue: bits_in_queue, rate: rate} = hashing) do
    if bits_in_queue == rate do
      hashing
      |> keccak_absorb()
    else
      hashing
    end
  end

  defp pad_and_switch_to_squeezing_phase(%Keccak{rate: rate} = hashing) do
    hashing
    |> update_data_queue_end()
    |> pad_and_switch_to_squeezing_phase_path()
    |> full_squeeze()
    |> partial_squeeze()
    |> state_end()
    |> keccak_permutation()
    |> keccak_extract()
    |> set_bits_in_queue(rate)
  end

  defp pad_and_switch_to_squeezing_phase(%Keccak{} = hashing) do
    hashing
  end

  defp state_end(%Keccak{state: state, rate: rate} = hashing) do
    value = Enum.at(state, (rate - 1) >>> 6)
    fixed = value ^^^ (1 <<< 63)
    replaced = List.replace_at(state, (rate - 1) >>> 6, fixed)

    %{hashing | state: replaced}
  end

  defp keccak_extract(%Keccak{rate: rate} = hashing) do
    hashing
    |> keccak_extract_loop(0, rate >>> 6, 0)
  end

  defp keccak_extract_loop(%Keccak{state: state, data_queue: data_queue} = hashing, index, length, offset) when index < length do
    <<h::8, g::8, f::8, e::8, d::8, c::8, b::8, a::8>> = <<Enum.at(state, index)::64>>

    replaced =
      data_queue
      |> List.replace_at(offset, a)
      |> List.replace_at(offset + 1, b)
      |> List.replace_at(offset + 2, c)
      |> List.replace_at(offset + 3, d)
      |> List.replace_at(offset + 4, e)
      |> List.replace_at(offset + 5, f)
      |> List.replace_at(offset + 6, g)
      |> List.replace_at(offset + 7, h)

    %{hashing | data_queue: replaced}
    |> keccak_extract_loop(index + 1, length, offset + 8)
  end

  defp keccak_extract_loop(%Keccak{} = hashing, _index, _length, _offset), do: hashing

  defp update_data_queue_end(%Keccak{data_queue: data_queue, bits_in_queue: bits_in_queue} = hashing) do
    replaced = List.replace_at(data_queue, bits_in_queue >>> 3, 1 <<< (bits_in_queue &&& 7))
    %{hashing | data_queue: replaced, bits_in_queue: bits_in_queue + 1}
  end

#  defp offset_to_zero(%Keccak{} = hashing) do
#    %{hashing | offset: 0}
#  end

  defp keccak_permutation(%Keccak{} = hashing) do
    hashing
    |> keccak_permutation_for(0)
  end

  defp keccak_permutation_for(%Keccak{state: state} = hashing, index) when index < 24 do
    a00 = Enum.at(state, 0)
    a01 = Enum.at(state, 1)
    a02 = Enum.at(state, 2)
    a03 = Enum.at(state, 3)
    a04 = Enum.at(state, 4)
    a05 = Enum.at(state, 5)
    a06 = Enum.at(state, 6)
    a07 = Enum.at(state, 7)
    a08 = Enum.at(state, 8)
    a09 = Enum.at(state, 9)
    a10 = Enum.at(state, 10)
    a11 = Enum.at(state, 11)
    a12 = Enum.at(state, 12)
    a13 = Enum.at(state, 13)
    a14 = Enum.at(state, 14)
    a15 = Enum.at(state, 15)
    a16 = Enum.at(state, 16)
    a17 = Enum.at(state, 17)
    a18 = Enum.at(state, 18)
    a19 = Enum.at(state, 19)
    a20 = Enum.at(state, 20)
    a21 = Enum.at(state, 21)
    a22 = Enum.at(state, 22)
    a23 = Enum.at(state, 23)
    a24 = Enum.at(state, 24)

    #theta
    c0 = a00 ^^^ a05 ^^^ a10 ^^^ a15 ^^^ a20
    c1 = a01 ^^^ a06 ^^^ a11 ^^^ a16 ^^^ a21
    c2 = a02 ^^^ a07 ^^^ a12 ^^^ a17 ^^^ a22
    c3 = a03 ^^^ a08 ^^^ a13 ^^^ a18 ^^^ a23
    c4 = a04 ^^^ a09 ^^^ a14 ^^^ a19 ^^^ a24

    d1 = (c1 <<< 1 ||| c1 >>> 0x3f) ^^^ c4 &&& 0xFFFFFFFFFFFFFFFF
    d2 = (c2 <<< 1 ||| c2 >>> 0x3f) ^^^ c0 &&& 0xFFFFFFFFFFFFFFFF
    d3 = (c3 <<< 1 ||| c3 >>> 0x3f) ^^^ c1 &&& 0xFFFFFFFFFFFFFFFF
    d4 = (c4 <<< 1 ||| c4 >>> 0x3f) ^^^ c2 &&& 0xFFFFFFFFFFFFFFFF
    d0 = (c0 <<< 1 ||| c0 >>> 0x3f) ^^^ c3 &&& 0xFFFFFFFFFFFFFFFF

    a00 = a00 ^^^ d1
    a05 = a05 ^^^ d1
    a10 = a10 ^^^ d1
    a15 = a15 ^^^ d1
    a20 = a20 ^^^ d1

    a01 = a01 ^^^ d2
    a06 = a06 ^^^ d2
    a11 = a11 ^^^ d2
    a16 = a16 ^^^ d2
    a21 = a21 ^^^ d2

    a02 = a02 ^^^ d3
    a07 = a07 ^^^ d3
    a12 = a12 ^^^ d3
    a17 = a17 ^^^ d3
    a22 = a22 ^^^ d3

    a03 = a03 ^^^ d4
    a08 = a08 ^^^ d4
    a13 = a13 ^^^ d4
    a18 = a18 ^^^ d4
    a23 = a23 ^^^ d4

    a04 = a04 ^^^ d0
    a09 = a09 ^^^ d0
    a14 = a14 ^^^ d0
    a19 = a19 ^^^ d0
    a24 = a24 ^^^ d0

    # rho/pi

    c1  = a01 <<<  1 ||| a01 >>> 63
    a01 = a06 <<< 44 ||| a06 >>> 20
    a06 = a09 <<< 20 ||| a09 >>> 44
    a09 = a22 <<< 61 ||| a22 >>>  3
    a22 = a14 <<< 39 ||| a14 >>> 25
    a14 = a20 <<< 18 ||| a20 >>> 46
    a20 = a02 <<< 62 ||| a02 >>>  2
    a02 = a12 <<< 43 ||| a12 >>> 21
    a12 = a13 <<< 25 ||| a13 >>> 39
    a13 = a19 <<<  8 ||| a19 >>> 56
    a19 = a23 <<< 56 ||| a23 >>>  8
    a23 = a15 <<< 41 ||| a15 >>> 23
    a15 = a04 <<< 27 ||| a04 >>> 37
    a04 = a24 <<< 14 ||| a24 >>> 50
    a24 = a21 <<<  2 ||| a21 >>> 62
    a21 = a08 <<< 55 ||| a08 >>>  9
    a08 = a16 <<< 45 ||| a16 >>> 19
    a16 = a05 <<< 36 ||| a05 >>> 28
    a05 = a03 <<< 28 ||| a03 >>> 36
    a03 = a18 <<< 21 ||| a18 >>> 43
    a18 = a17 <<< 15 ||| a17 >>> 49
    a17 = a11 <<< 10 ||| a11 >>> 54
    a11 = a07 <<<  6 ||| a07 >>> 58
    a07 = a10 <<<  3 ||| a10 >>> 61
    a10 = c1

    # chi

    c0  = a00 ^^^ (~~~a01 &&& a02) &&& 0xFFFFFFFFFFFFFFFF
    c1  = a01 ^^^ (~~~a02 &&& a03) &&& 0xFFFFFFFFFFFFFFFF
    a02 = a02 ^^^ (~~~a03 &&& a04) &&& 0xFFFFFFFFFFFFFFFF
    a03 = a03 ^^^ (~~~a04 &&& a00) &&& 0xFFFFFFFFFFFFFFFF
    a04 = a04 ^^^ (~~~a00 &&& a01) &&& 0xFFFFFFFFFFFFFFFF
    a00 = c0
    a01 = c1

    c0  = a05 ^^^ (~~~a06 &&& a07) &&& 0xFFFFFFFFFFFFFFFF
    c1  = a06 ^^^ (~~~a07 &&& a08) &&& 0xFFFFFFFFFFFFFFFF
    a07 = a07 ^^^ (~~~a08 &&& a09) &&& 0xFFFFFFFFFFFFFFFF
    a08 = a08 ^^^ (~~~a09 &&& a05) &&& 0xFFFFFFFFFFFFFFFF
    a09 = a09 ^^^ (~~~a05 &&& a06) &&& 0xFFFFFFFFFFFFFFFF
    a05 = c0
    a06 = c1

    c0  = a10 ^^^ (~~~a11 &&& a12) &&& 0xFFFFFFFFFFFFFFFF
    c1  = a11 ^^^ (~~~a12 &&& a13) &&& 0xFFFFFFFFFFFFFFFF
    a12 = a12 ^^^ (~~~a13 &&& a14) &&& 0xFFFFFFFFFFFFFFFF
    a13 = a13 ^^^ (~~~a14 &&& a10) &&& 0xFFFFFFFFFFFFFFFF
    a14 = a14 ^^^ (~~~a10 &&& a11) &&& 0xFFFFFFFFFFFFFFFF
    a10 = c0
    a11 = c1

    c0  = a15 ^^^ (~~~a16 &&& a17) &&& 0xFFFFFFFFFFFFFFFF
    c1  = a16 ^^^ (~~~a17 &&& a18) &&& 0xFFFFFFFFFFFFFFFF
    a17 = a17 ^^^ (~~~a18 &&& a19) &&& 0xFFFFFFFFFFFFFFFF
    a18 = a18 ^^^ (~~~a19 &&& a15) &&& 0xFFFFFFFFFFFFFFFF
    a19 = a19 ^^^ (~~~a15 &&& a16) &&& 0xFFFFFFFFFFFFFFFF
    a15 = c0
    a16 = c1

    c0  = a20 ^^^ (~~~a21 &&& a22) &&& 0xFFFFFFFFFFFFFFFF
    c1  = a21 ^^^ (~~~a22 &&& a23) &&& 0xFFFFFFFFFFFFFFFF
    a22 = a22 ^^^ (~~~a23 &&& a24) &&& 0xFFFFFFFFFFFFFFFF
    a23 = a23 ^^^ (~~~a24 &&& a20) &&& 0xFFFFFFFFFFFFFFFF
    a24 = a24 ^^^ (~~~a20 &&& a21) &&& 0xFFFFFFFFFFFFFFFF
    a20 = c0
    a21 = c1

    # iota
    a00 = a00 ^^^ Enum.at(@keccak_round_constants, index)

    edit = [a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11, a12,
    a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24]

    keccak_permutation_for(%{hashing | state: edit}, index + 1)
  end

  defp keccak_permutation_for(%Keccak{} = hashing, _index), do: hashing
end