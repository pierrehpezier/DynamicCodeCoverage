
all: clean utils

utils:
	cl /c /EHsc utils.cpp /I.. /DBUILD_UTIL
	lib utils.obj

clean:
	rm -rf *obj *lib *exe

test:
	cl /c /EHsc test.cpp /I..
	link  test.obj utils.lib ..\cryptopp\Win32\Output\Release\cryptlib.lib
