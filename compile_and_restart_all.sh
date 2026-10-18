#!/bin/bash
cd /home/ebuu/elixip/apps/kelixip       && MIX_ENV=prod mix release kelixip --overwrite
cd /home/ebuu/elixip/apps/kelix_modules && MIX_ENV=prod mix compile
cd /home/ebuu/elixip
# releases/COOKIE is the node's per-host secret, not part of the build: `mix
# release` writes a fresh random one into _build, and copying it over would
# change the cookie kelictl and remote shells authenticate with on every run.
sudo rsync -a --delete --exclude modules/ --exclude tmp/ --exclude /releases/COOKIE \
   _build/prod/rel/kelixip/ /usr/lib/kelixip/
sudo chown -R root:root /usr/lib/kelixip
# Same rule as the package's %post: generated once, kept afterwards.
COOKIE=/usr/lib/kelixip/releases/COOKIE
if ! sudo test -s "$COOKIE"; then
   head -c 32 /dev/urandom | base64 | sudo tee "$COOKIE" > /dev/null
fi
sudo chown root:kelixip "$COOKIE"
sudo chmod 0640 "$COOKIE"
sudo cp _build/prod/lib/kelix_modules/ebin/Elixir.Kelix.Mod.*.beam /usr/lib/kelixip/modules/
sudo systemctl restart kelixip
sudo systemctl restart mediaserver
