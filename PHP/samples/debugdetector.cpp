#include <windows.h>

int main(void)
{
	if(IsDebuggerPresent())
		MessageBoxA(0, "Debugger detected", NULL, 0);
	else
		MessageBoxA(0, "Debugger NOT detected", NULL, 0);
	return 0;
}

