#include "utils.cpp"


std::ofstream TraceFile;


VOID printip(VOID *ip)
{
  TraceFile << "E;" std::hex << ip << std::endl;
}

VOID Instruction(INS ins, VOID *v)
{
  IMG currentimg = IMG_FindByAddress(INS_Address(ins));
  if(IMG_Valid(currentimg) && IMG_IsMainExecutable(currentimg)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);
  }
}

VOID Fini(INT32 code, VOID *v)
{
    TraceFile <<  "#eof" << std::endl;
    TraceFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    PIN_ERROR("This Pintool prints the IPs of every instruction executed\n"
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char * argv[])
{
    TraceFile.open("Coverage_" +  PIN_GetPid() + ".out", "w");
    // Initialize pin
    if (PIN_Init(argc, argv)) {
      return Usage();
    }
    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);
    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    // Start the program, never returns
    PIN_StartProgram();
    return 0;
}
