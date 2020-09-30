all: clean debuggerdetector

debuggerdetector:
	make -C utils
	cl /MT /EHs- /EHa- /wd4530 /DTARGET_WINDOWS /DBIGARRAY_MULTIPLIER=1 /D_CRT_SECURE_NO_DEPRECATE /D_SECURE_SCL=0 /nologo /Gy /DTARGET_IA32 /DHOST_IA32 /I../../../source/include/pin /I../../../source/include/pin/gen /I../../../extras/components/include /I../../../extras/xed-ia32/include /I../../../source/tools/InstLib /Icryptopp /I. /O2  /c /Foobj-ia32/debuggerdetector.obj debuggerdetector.cpp
	link /DLL /EXPORT:main /NODEFAULTLIB /NOLOGO /INCREMENTAL:NO /MACHINE:x86 /ENTRY:Ptrace_DllMainCRTStartup@12 /BASE:0x55000000 /OPT:REF  /out:obj-ia32/debuggerdetector.dll obj-ia32/debuggerdetector.obj  /LIBPATH:../../../ia32/lib /LIBPATH:../../../ia32/lib-ext  /LIBPATH:utils /LIBPATH:./cryptopp/Win32/Output/Release/ /LIBPATH:../../../extras/xed-ia32/lib pin.lib libxed.lib libcpmt.lib libcmt.lib pinvm.lib kernel32.lib ntdll-32.lib utils.lib cryptlib.lib advapi32.lib

clean:
	make -C utils clean
	rm -rf obj-ia32
	mkdir obj-ia32
