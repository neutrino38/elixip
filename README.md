# Elixip

**Elixip is a personal project to write a multipurpose SIP application server.**

The idea is to write a generic SIP server. Actual SIP application will be separated
processes (possibily on other nodes) and will be able to register dispatching rules
a bit like in SIP servlet.

The idea would also be to see how we can take advantages of elixir / erlang features
to implement distributed SIP processing and redundancy on several servers.

This is not intended to be a finished product . It is rather a self training project.

## Design and future roadmap

### Goal

I changed my mind and I now want to build and advanced SIP and RTP test tool using the Elixir scripting capablity.

What I want is to use the Domain Specific Language capability of elixir to create
an easy and powerful scripting tools to test WebRTC call scenario. The signaling
would be SIP over WSS or SIP over UDP or TCP and the media would be using
mendooze media server 

https://github.com/1760002018/medooze-media-server/tree/main/media-server

