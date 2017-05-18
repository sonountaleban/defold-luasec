/*--------------------------------------------------------------------------
 * LuaSec 0.6
 * Copyright (C) 2006-2016 Bruno Silvestre
 *
 *--------------------------------------------------------------------------*/

#ifndef LSEC_CONFIG_H
#define LSEC_CONFIG_H

#if defined(_WIN32)
#define LSEC_API __declspec(dllexport) 
#else
#define LSEC_API extern
#endif

#define LUASOCKET_DEBUG
#define WITH_LUASOCKET

// Extension lib defines
#define LIB_NAME "LuaSec"
#define MODULE_NAME "luasec"

#if (LUA_VERSION_NUM == 501)
#define setfuncs(L, MOD, R)    luaL_register(L, MOD, R)
#define lua_rawlen(L, i)  lua_objlen(L, i)
#define luaL_newlib(L, MOD, R) do { lua_newtable(L); luaL_register(L, MOD, R); } while(0)
#else
#define setfuncs(L, R) luaL_setfuncs(L, R, 0)
#endif

#endif
