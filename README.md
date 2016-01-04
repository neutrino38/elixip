# Elixip

**Elixip is a personal project to write a multipurpose SIP application server.**

The idea is to write a generic SIP server. Actual SIP application will be separated
processes (possibily on other nodes) and will be able to register dispatching rules
a bit like in SIP servlet.

The idea would also be to see how we can take advantages of elixir / erlang features
to implement distributed SIP processing and redundancy on several servers.

This is not intended to be a finished product . It is rather a self training project.

## Design and future roadmap

### Beta version

A regular Elixir project with a callback based API that can be embedded to produce ability
SIP application.

### Future version

The main idea is to run the SIP stack into separates erlang nodes. The SIP applications
would run in separates nodes (one node per set of domain that can run multiple application).
Application would embbed a simple SIP API that would enable the applications to be fully
isolated from the code SIP and possibly distributed accross several servers.

### Redundent version

The ability to run several instances of network listeners and as well as several instances
of the same pplication on several nodes. One more step would to integrate cloud APIs to enable
dynamic instance creation. This would make possible to create or delete instance to cope with
increasing traffic.

### Mutliple protocols (H.323)

Same approach would be used to create other listener to support other signalling protocols
and allow the design of multi protocol applications such as gateways.

A further development of this project would allow

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
