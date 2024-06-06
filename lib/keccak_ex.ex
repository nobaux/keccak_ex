defmodule KeccakEx do
  @moduledoc """
  Implementation of Keccak in pure Elixir.
  """

  @spec hash_256(bitstring()) :: nil | <<_::8, _::_*1>>
  @doc """
  Returns the keccak hash 256
  """
  def hash_256(input) do
    Hash.Hash256.hash(input)
  end

  @spec hash_512(bitstring()) :: nil | <<_::8, _::_*1>>
  @doc """
  Returns the keccak hash 512
  """
  def hash_512(input) do
    Hash.Hash512.hash(input)
  end
end
