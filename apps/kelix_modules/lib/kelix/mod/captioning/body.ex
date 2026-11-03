defmodule Kelix.Mod.Captioning.Body do
  @moduledoc """
  The `application/captioning+xml` body of the captioning INFO and of its `200 OK`
  (call-captioning spec §6.2, §6.4).

      <captioning>
        <inbound>
          <stt comp="true"/>
        </inbound>
      </captioning>

  `<inbound>` is the direction towards the user, as the CLIENT sees it: `<stt>`
  there asks for the transcription of the other party — the captions — and
  `comp="true"` for the correction of what the user types. Nothing to do with
  kelixip's `inbound` leg (the caller's): the mapping is read once, here.

  The body comes from the network. It is bounded (#{div(4096, 1024)} KiB), a
  `<!DOCTYPE` in its prolog is refused, and it goes to `:erlsom`, which resolves
  nothing external and leaves names as strings — never to a parser that makes
  atoms of the element names it is sent. Only `captioning/inbound/stt@comp` is
  read; every other element and attribute is ignored (§6.4, extensibility).
  """

  @content_type "application/captioning+xml"
  @max_body 4096

  @doc "The media type of the body, both ways."
  @spec content_type() :: String.t()
  def content_type(), do: @content_type

  @doc """
  Read a request body. `stt` is whether `<inbound><stt>` is there, `comp` whether
  it asks for the correction: an absent `comp` is `false`, and so is `comp`
  without `<stt>`.
  """
  @spec parse(binary() | nil) :: {:ok, %{stt: boolean, comp: boolean}} | {:error, term}
  def parse(body) when is_binary(body) do
    with :ok <- check_size(body),
         :ok <- check_no_doctype(body),
         {:ok, root} <- scan(body) do
      read_root(root)
    end
  end

  def parse(_no_body), do: {:error, :no_body}

  @doc """
  The body of a `200 OK`: `comp="false"` without a `uri`, or `comp="true"` with
  the URL of the correction stream.
  """
  @spec render(%{required(:comp) => boolean, optional(:uri) => String.t()}) :: binary
  def render(%{comp: true, uri: uri}) when is_binary(uri),
    do: document(~s(<stt comp="true" uri="#{escape(uri)}"/>))

  def render(%{comp: _}), do: document(~s(<stt comp="false"/>))

  defp document(stt) do
    ~s(<?xml version="1.0" encoding="UTF-8"?>\n) <>
      "<captioning>\n  <inbound>\n    " <> stt <> "\n  </inbound>\n</captioning>\n"
  end

  defp escape(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
  end

  defp check_size(body) when byte_size(body) > @max_body,
    do: {:error, {:body_too_large, byte_size(body)}}

  defp check_size(_body), do: :ok

  # Only the prolog can declare a doctype; past the first element it is text.
  defp check_no_doctype(body) do
    prolog = body |> String.split(~r/<[A-Za-z_]/, parts: 2) |> hd()
    if prolog =~ ~r/<!DOCTYPE/i, do: {:error, :doctype_not_allowed}, else: :ok
  end

  defp scan(body) do
    case :erlsom.simple_form(body, output_encoding: :utf8) do
      {:ok, root, _tail} -> {:ok, root}
      {:error, reason} -> {:error, {:malformed_xml, reason}}
    end
  catch
    _kind, reason -> {:error, {:malformed_xml, reason}}
  end

  defp read_root({name, _attrs, children}) do
    case local_name(name) do
      "captioning" ->
        case find(children, "inbound") do
          {_name, _attrs, inbound} ->
            case find(inbound, "stt") do
              {_name, attrs, _children} -> {:ok, %{stt: true, comp: comp?(attrs)}}
              nil -> {:ok, %{stt: false, comp: false}}
            end

          nil ->
            {:ok, %{stt: false, comp: false}}
        end

      other ->
        {:error, {:not_a_captioning_document, other}}
    end
  end

  defp find(children, local) do
    Enum.find(children, fn
      {name, _attrs, _children} -> local_name(name) == local
      _text -> false
    end)
  end

  defp comp?(attrs) do
    Enum.any?(attrs, fn {name, value} ->
      local_name(name) == "comp" and
        value |> to_string() |> String.trim() |> String.downcase() == "true"
    end)
  end

  # erlsom names an element in a namespace `'{namespace}local'`, a prefixed one
  # `'prefix:local'` when the prefix is undeclared; the local part is what counts.
  defp local_name(name) do
    name
    |> to_string()
    |> String.split("}")
    |> List.last()
    |> String.split(":")
    |> List.last()
  end
end
