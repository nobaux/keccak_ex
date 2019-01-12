defmodule KeccakExTest do
  use ExUnit.Case
  doctest KeccakEx

  test "basic" do
    hash = "7adf4255f518ca27b9b41ddfd97d4a3799e02347b3b1b7c525b67371b3db350a571b3bddb9732868daeab70f9ac9bd842c8b26e605855899f32f8526c2e6d5ed"
    |> Base.decode16!(case: :mixed)
    |> KeccakEx.hash()

    assert hash == <<170, 68, 45, 42, 41, 217, 15, 232, 186, 206, 34, 243, 192, 82,
             108, 106, 223, 154, 173, 171, 167, 80, 45, 69, 65, 191, 240, 51,
             185, 140, 72, 181>>
  end
end