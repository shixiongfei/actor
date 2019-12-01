solution ( "actor" )
  configurations { "Release", "Debug" }
  platforms { "x64" }

  if _ACTION == "clean" then
    os.rmdir(".vs")
    os.rmdir("bin")
    os.remove("actor.VC.db")
    os.remove("actor.sln")
    os.remove("actor.vcxproj")
    os.remove("actor.vcxproj.filters")
    os.remove("actor.vcxproj.user")
    os.remove("actor.make")
    os.remove("test.vcxproj")
    os.remove("test.vcxproj.filters")
    os.remove("test.vcxproj.user")
    os.remove("test.make")
    os.remove("Makefile")
    return
  end

  -- A project defines one build target
  project ( "actor" )
  kind ( "SharedLib" )
  language ( "C" )
  targetname ("actor")
  files { "./*.h", "./*.c" }
  excludes { "./test.c" }
  defines { "_UNICODE", "ACTOR_BUILD_DLL" }
  staticruntime "On"

  configuration ( "Release" )
    optimize "On"
    objdir ( "./bin/tmp" )
    targetdir ( "./bin" )
    defines { "NDEBUG", "_NDEBUG" }

  configuration ( "Debug" )
    symbols "On"
    objdir ( "./bin/tmp" )
    targetdir ( "./bin" )
    defines { "DEBUG", "_DEBUG" }

  configuration ( "vs*" )
    defines { "WIN32", "_WIN32", "_WINDOWS",
              "_CRT_SECURE_NO_WARNINGS", "_CRT_SECURE_NO_DEPRECATE",
              "_CRT_NONSTDC_NO_DEPRECATE", "_WINSOCK_DEPRECATED_NO_WARNINGS" }
    links { "Ws2_32", "IPHLPAPI" }

  configuration ( "gmake" )
    warnings  "Default" --"Extra"
    defines { "LINUX_OR_MACOSX" }
    links { }

  configuration { "gmake", "macosx" }
    defines { "__APPLE__", "__MACH__", "__MRC__", "macintosh" }

  configuration { "gmake", "linux" }
    defines { "__linux__" }
    links { "pthread" }

  -- A project defines one build target
  project ( "test" )
  kind ( "ConsoleApp" )
  language ( "C" )
  targetname ("test")
  files { "./test.c" }
  defines { "_UNICODE" }
  links { "actor" }
  staticruntime "On"

  configuration ( "Release" )
    optimize "On"
    objdir ( "./bin/tmp" )
    targetdir ( "./bin" )
    defines { "NDEBUG", "_NDEBUG" }

  configuration ( "Debug" )
    symbols "On"
    objdir ( "./bin/tmp" )
    targetdir ( "./bin" )
    defines { "DEBUG", "_DEBUG" }

  configuration ( "vs*" )
    defines { "WIN32", "_WIN32", "_WINDOWS",
              "_CRT_SECURE_NO_WARNINGS", "_CRT_SECURE_NO_DEPRECATE",
              "_CRT_NONSTDC_NO_DEPRECATE", "_WINSOCK_DEPRECATED_NO_WARNINGS" }

  configuration ( "gmake" )
    warnings  "Default" --"Extra"
    defines { "LINUX_OR_MACOSX" }

  configuration { "gmake", "macosx" }
    defines { "__APPLE__", "__MACH__", "__MRC__", "macintosh" }

  configuration { "gmake", "linux" }
    defines { "__linux__" }
