--WAF init (run by init_by_lua_file at nginx startup)
--Preload config and lib modules so they are cached for per-request access phase
require 'config'
require 'lib'
