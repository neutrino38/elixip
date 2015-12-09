# Elixip

**Elixip is a personal project to write a multipurpose SIP application server.**

The idea is to write a generic SIP server. Actual SIP application will be separated
processes (possibily on other nodes) and will be able to register dispatching rules
a bit like in SIP servlet.

The idea would also be to see how we can take advantages of elixir / erlang feature
to implement distributed SIP processing and redundancy on several servers.

This is not intended to be a finished product . It is rather a self training project.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add socket_server to your list of dependencies in `mix.exs`:

        def deps do
          [{:socket_server, "~> 0.0.1"}]
        end

  2. Ensure socket_server is started before your application:

        def application do
          [applications: [:socket_server]]
        end
