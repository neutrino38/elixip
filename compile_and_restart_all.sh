#!/bin/bash
cd /home/ebuu/elixip/apps/kelixip       && MIX_ENV=prod mix release kelixip --overwrite
cd /home/ebuu/elixip/apps/kelix_modules && MIX_ENV=prod mix compile
cd /home/ebuu/elixip
sudo rsync -a --delete --exclude modules/ --exclude tmp/ \
   _build/prod/rel/kelixip/ /usr/lib/kelixip/
sudo chown -R root:root /usr/lib/kelixip
sudo cp _build/prod/lib/kelix_modules/ebin/Elixir.Kelix.Mod.*.beam /usr/lib/kelixip/modules/
sudo systemctl restart kelixip
sudo systemctl restart mediaserver

