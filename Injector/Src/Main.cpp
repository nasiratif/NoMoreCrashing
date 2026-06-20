/*

	NoMoreCrashing DLL Injector v1.0
	Authored by Nassic (https://github.com/nasiratif/NoMoreCrashing)

*/

#include "Hook.hpp"

#include <Windows.h>
#define BEA_ENGINE_STATIC
#include <beaengine/BeaEngine.h>

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ePtrs)
{
	DISASM disasm = {};
	if (ePtrs->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && ePtrs->ExceptionRecord->ExceptionInformation[0] == 0x8)
#ifdef _WIN64
	{
		// If we got an execution violation we must set the instruction pointer back to the return address
		ePtrs->ContextRecord->Rip = *(DWORD64*)ePtrs->ContextRecord->Rsp;
		// gotta make sure to pop the return address too
		ePtrs->ContextRecord->Rsp += sizeof(DWORD64);
	}
	else
	{
		// Simply advance to the next instruction:
		disasm.EIP = ePtrs->ContextRecord->Rip;
		ePtrs->ContextRecord->Rip += Disasm(&disasm);
	}
#else
	{
		ePtrs->ContextRecord->Eip = *(DWORD*)ePtrs->ContextRecord->Esp;
		ePtrs->ContextRecord->Esp += sizeof(DWORD);
	}
	else
	{
		disasm.EIP = ePtrs->ContextRecord->Eip;
		ePtrs->ContextRecord->Eip += Disasm(&disasm);
	}
#endif

	return EXCEPTION_CONTINUE_EXECUTION;
}

LPTOP_LEVEL_EXCEPTION_FILTER prevFilter = ExceptionHandler;
// We'll need to hook in a stub exception filter in the case that the program tries to set it's own filter after this DLL has been loaded (pretty much always if the DLL is loaded on process creation)
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI FilterStub(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
	// Simulating SetUnhandledExceptionFilter's behavior definitely isn't necessary but I'm doing so just to be on the safe side (I'm thinking what if a program has anti-exception-filter measures that test that the return values of SetUnhandledExceptionFilter always returns the previous ones? lol)
	auto ret = prevFilter;
	prevFilter = lpTopLevelExceptionFilter;
	return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		SetUnhandledExceptionFilter(ExceptionHandler);
		InstallHook(SetUnhandledExceptionFilter, FilterStub);
	}
	return TRUE;
}