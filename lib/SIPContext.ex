defmodule SIP.Context do
  @moduledoc """
  A SIP session context is a struct that store SIP user agent propertie (username, auth, etc. for a SIP session)
  A SIP context is local to a session process
  """
  @props [ :username, :displayname, :authusername, :domain, :ha1, :ha1b, :algorithm, :ftag, :debug, :dialogpid, :lasterr ]

  defstruct [
    username: nil,
    authusername: nil,
    displayname: nil,
    domain: nil,
    ha1: nil,
    ha1b: nil,
    algorithm: "MD5",
    ftag: nil,
    debug: false,
    dialogpid: nil,
    lasterr: :ok,
    appdata: %{}
  ]

  defmacro __using__(_opts) do
    quote do
      # Déclare la macro ctx_set
      defmacro ctx_set(prop, value) do
        quote do
          var!(sip_ctx) = SIP.Context.set(var!(sip_ctx), unquote(prop), unquote(value))
        end
      end

      defmacro ctx_get(prop) do
        quote do
          SIP.Context.get(var!(sip_ctx), unquote(prop))
        end
      end

      defmacro appdata_set(prop, value) do
        quote do
          appdata = Map.put(var!(sip_ctx).appdata, unquote(prop), unquote(value))
          var!(sip_ctx) = Map.put(var!(sip_ctx), :appdata, appdata)
        end
      end

      defmacro appdata_get(prop) do
        quote do
          Map.get(var!(sip_ctx.appdata), unquote(prop))
        end
      end

      defmacro ctx_set_multiple(proplist) do
        quote do
          var!(sip_ctx) = SIP.Context.set( var!(sip_ctx), unquote(proplist) )
        end
      end

      defmacro ctx_from() do
        quote do
          SIP.Context.from(var!(sip_ctx))
        end
      end

      defmacro ctx_to(userpart) do
        quote do
          SIP.Context.to(var!(sip_ctx), unquote(userpart))
        end
      end

    end
  end

  def get(context, prop) when prop in @props do
    Map.get(context, prop)
  end

  def get(context, prop) when is_atom(prop) do
    Map.get(context.appdata, prop)
  end

  @spec set(map(), list()) :: list()
  def set(context, []) do
    context
  end

  def set(context, proplist) when is_list(proplist) do
    [ { prop, value } | remaining ] = proplist
    new_ctx = set(context, prop, value)
    set(new_ctx, remaining)
  end

  # Set the username and create the fromtag if needed
  def set(context, :username, value) when is_binary(value) do
    context = if is_nil(context.ftag) do
      Map.put(context, :ftag, SIP.Msg.Ops.generate_from_or_to_tag())
    end
    Map.put(context, :username, value)
  end

  # Set a single property that is already int he map
  def set(context, prop, value) when prop in @props and is_binary(value) do
    Map.put(context, prop, value)
  end

  # Set the dialog PID
  def set(context, :dialogpid, value) do
    if is_pid(value) do
      Map.put(context, :dialogpid, value)
    else
      raise "dialog PID must me a process ID"
    end
  end

  # Set the password
  def set(ctx, :passwd, value) when ctx.authusername != nil and ctx.algorithm != nil and ctx.domain != nil do
    Map.put( ctx, :ha1,
      SIP.Auth.compute_ha1(ctx.algorithm, ctx.authusername, ctx.domain, value) )
  end

  def set(ctx, :passwd, _value) when is_nil(ctx.authusername) or is_nil(ctx.algorithm) or is_nil(ctx.domain) do
    raise "Cannot set password. One of the following has not been set: authusername, domain, algorithm"
  end

  def set(ctx, :lasterr, value) do
    Map.put( ctx, :lasterr, value)
  end

  def set(_context, prop, _value) when is_atom(prop) do
    raise "Unsupported context property #{prop}"
  end

  def from(context) do
    from_uri = %SIP.Uri{
      displayname: context.displayname,
      userpart: context.username,
      domain: context.domain,
      params: %{ "tag" => context.ftag }
    }

    if from_uri.userpart == nil or from_uri.domain == nil do
      raise "username or domain has not been set"
    else
      from_uri
    end
  end


  def to( context, userpart ) do
    if is_nil(context.domain), do: raise "domain has not been set"
    userpart = if userpart != nil, do: userpart, else: context.username
    to_uri = %SIP.Uri{
      userpart: userpart,
      domain: context.domain
    }

    if to_uri.userpart == nil do
      raise "username not been set"
    else
      to_uri
    end
  end


end
