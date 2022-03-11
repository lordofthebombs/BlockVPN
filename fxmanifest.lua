fx_version "cerulean"
game "gta5"

lua54 "yes"

author "lordofthebombs"
description "Blocks suspected VPN IP addresses from connecting to the server."
version "1.1.2"

client_script "cl_blockvpn.lua"
server_script "@mysql-async/lib/MySQL.lua"
server_script "sv_blockvpn.lua"
