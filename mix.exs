defmodule KeccakEx.MixProject do
  use Mix.Project

  @source_url "https://github.com/N-0x90/keccak_ex"

  def project do
    [
      app: :keccak_ex,
      version: "0.4.0",
      elixir: "~> 1.16.0",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @source_url,
      name: "KeccakEx"
    ]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.34.0", only: :dev, runtime: false},
      {:binary, "~> 0.0.5"},
      {:benchee, "~> 1.0", only: :test},
    ]
  end

  defp description do
    """
    Implementation of Keccak 256/512 in pure Elixir.
    """
  end

  defp package do
    [
      files: ["lib", "test", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["N0x90"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end
end
