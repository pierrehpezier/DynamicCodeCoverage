#include "pin.H"
namespace WINDOWS {
	#include <windows.h>
	#include <stdio.h>
}
//custom imports
#include "utils/utils.h"
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "cmcfg32.lib")

#define LIMIT_SIZE
#define LIMIT_TRACE_SIZE
//#define VERBOSE

utils::Logger mylogger;
UINT64 ins_count = 0;
ADDRINT baseoffset = 0;
PIN_LOCK pinLock;

INT32 Usage()
{
    cerr <<
        "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

VOID logaddr(ADDRINT addr, std::string *disassembled)
{
	ins_count++;
	addr -= baseoffset;
#ifdef LIMIT_TRACE_SIZE
	std::string logentry = std::string("X;") + std::to_string(addr) + std::string(";");
#else
	std::string logentry = std::string("X;") + std::to_string(addr) + std::string(";") + *disassembled;
#endif
	mylogger.AddEntry(logentry);
}

VOID MemEntry(std::string operation, VOID * ip, VOID * addr, UINT32 size)
{
#ifdef LIMIT_SIZE
	PIN_LockClient();
	IMG targetimg = IMG_FindByAddress((ADDRINT)addr);
	PIN_UnlockClient();
	if(!IMG_Valid(targetimg) || !IMG_IsMainExecutable(targetimg)) {
		return;
	}
#endif
	ip = (void *)((ADDRINT)ip - baseoffset);
	addr = (void *)((ADDRINT)addr - baseoffset);
#ifdef LIMIT_TRACE_SIZE
	std::string logentry = operation + std::string(";") + std::to_string((size_t)ip) + std::string(";") + std::to_string((size_t)addr) + std::string(";") + std::to_string(size) + std::string(";");
#else
	unsigned char *buffer = new unsigned char[size];
	PIN_SafeCopy(buffer, addr, size);
	std::string rawdata = utils::Logger::Bin2hex(buffer, size);
	delete[] buffer;
	std::string logentry = operation + std::string(";") + std::to_string((size_t)ip) + std::string(";") + std::to_string((size_t)addr) + std::string(";") + rawdata;
#endif
	mylogger.AddEntry(logentry);
}

VOID RecordMemRead(VOID * ip, VOID * addr, UINT32 size)
{
	MemEntry("R", ip, addr, size);
}

VOID RecordMemWrite(VOID * ip, VOID * addr, UINT32 size)
{	
    MemEntry("W", ip, addr, size);
}

VOID Instruction(INS ins, VOID *v)
{
	PIN_LockClient();
	IMG currentimg = IMG_FindByAddress(INS_Address(ins));
	PIN_UnlockClient();
	//Trace Execution
#ifdef LIMIT_SIZE
	if(!IMG_Valid(currentimg) || !IMG_IsMainExecutable(currentimg)) {
		return;
	}
#endif
	if(!baseoffset) {
		baseoffset = IMG_LowAddress(currentimg);
	}
	//Log execution
#ifdef LIMIT_TRACE_SIZE
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)logaddr, IARG_INST_PTR, IARG_PTR, new string(""), IARG_END);
#else
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)logaddr, IARG_INST_PTR, IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
#endif
	//Trace memory access (All images)
	if(!INS_IsStandardMemop(ins)) {
		return;
	}
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < memOperands; memOp++)
	{
		UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
		if (INS_MemoryOperandIsRead(ins, memOp)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_END);
		}
		if (INS_MemoryOperandIsWritten(ins, memOp) && INS_HasFallThrough(ins)) {
			INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_END);
		}
	}
}

VOID Fini(INT32 code, VOID *v)
{
		mylogger.AddEvent(LEVEL_INFO, "Process stop");
		mylogger.AddEvent(LEVEL_INFO, std::to_string(ins_count) + " Instructions catched");
		mylogger.close();
#ifdef VERBOSE
		utils::Logger::displaymessage("Debug finished");
#endif
}

BOOL FollowChild(CHILD_PROCESS childProcess, VOID * userData)
{
    INT Argc;
    const LEVEL_BASE::CHAR *const *Argv;
    CHILD_PROCESS_GetCommandLine(childProcess, 	&Argc, &Argv);
    std::string cmdline(Argv[0]);
    cmdline += " ";
    for(unsigned int i=1; i<Argc; i++) {
      if(i>1) {
        cmdline += " ";
      }
      cmdline += Argv[i];
    }
		mylogger.AddEvent(LEVEL_INFO, "New subprocess:" + cmdline);
#ifdef VERBOSE
		utils::Logger::displaymessage(cmdline.c_str());
#endif
    return TRUE;
}


VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&pinLock, threadid+1);
	mylogger.AddEvent(LEVEL_INFO, "Thread started: " + std::to_string(threadid));
    PIN_ReleaseLock(&pinLock);
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    PIN_GetLock(&pinLock, threadid+1);
	mylogger.AddEvent(LEVEL_INFO, "Thread stopped: " + std::to_string(threadid));
    PIN_ReleaseLock(&pinLock);
}

int main(int argc, char *argv[])
{
	if( PIN_Init(argc,argv) )
	{
	    return Usage();
	}
	std::string logfilename("debuggerdetector_" +  std::to_string(PIN_GetPid()) + ".txt.gz");
	mylogger.open(logfilename);
	mylogger.AddEvent(LEVEL_INFO, "Process loaded");
    //Calltrace
    INS_AddInstrumentFunction(Instruction, 0);
	//process management
	PIN_AddFollowChildProcessFunction(FollowChild, 0);
	PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);

    PIN_AddFiniFunction(Fini, 0);
	// Never returns
#ifdef VERBOSE
	utils::Logger::displaymessage("Last chance to debug software before starting debug process...");
#endif
	mylogger.AddEvent(LEVEL_INFO, "Process starting");
    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
