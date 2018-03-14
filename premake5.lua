workspace "DyingLight.BorderlessWindowedMode"
   configurations { "Release", "Debug" }
   architecture "x86_64"
   location "build"
   buildoptions {"-std:c++latest"}
   
   defines { "rsc_CompanyName=\"ThirteenAG\"" }
   defines { "rsc_LegalCopyright=\"MIT License\""} 
   defines { "rsc_FileVersion=\"1.0.0.0\"", "rsc_ProductVersion=\"1.0.0.0\"" }
   defines { "rsc_InternalName=\"%{prj.name}\"", "rsc_ProductName=\"%{prj.name}\"", "rsc_OriginalFilename=\"%{prj.name}.dll\"" }
   defines { "rsc_FileDescription=\"Borderless Windowed Mode for Dying Light\"" }
   defines { "rsc_UpdateUrl=\"https://github.com/ThirteenAG/DyingLight.BorderlessWindowedMode/releases\"" }
   
   defines { "X64" }
     
project "DyingLight.BorderlessWindowedMode"
   kind "SharedLib"
   language "C++"
   targetdir "bin/x64/%{cfg.buildcfg}"
   targetname "DyingLight.BorderlessWindowedMode"
   targetextension ".asi"
   
   includedirs { "source" }
   includedirs { "external" }
   
   files { "source/dllmain.cpp" }
   files { "source/resources/Versioninfo.rc" }
   files { "external/hooking/Hooking.Patterns.h", "external/hooking/Hooking.Patterns.cpp" }
   includedirs { "external/hooking" }
   includedirs { "external/injector/include" }
   
   characterset ("MBCS")
   
   filter "configurations:Debug"
      defines { "DEBUG" }
      symbols "On"

   filter "configurations:Release"
      defines { "NDEBUG" }
      optimize "On"
      flags { "StaticRuntime" }
	  