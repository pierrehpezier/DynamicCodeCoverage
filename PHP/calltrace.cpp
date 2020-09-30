#include "pin.H"
#include <iostream>
#include <fstream>

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "calltrace.out", "specify trace file name");
KNOB<BOOL>   KnobPrintArgs(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "print call arguments ");
//KNOB<BOOL>   KnobPrintArgs(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "mark indirect calls ");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool produces a call trace." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

string invalid = "invalid_rtn";

/* ===================================================================== */
const string *Target2String(ADDRINT target, ADDRINT source)
{
    string name = RTN_FindNameByAddress(target);
	PIN_LockClient();
    string imagename = IMG_Name(IMG_FindByAddress(target));
    string sourceimagename = IMG_Name(IMG_FindByAddress(source));

	PIN_UnlockClient();
    if (name == "")
        return &invalid;
    else
        return new string(sourceimagename + "->" + imagename + ":" + name);
}

/* ===================================================================== */

VOID  do_call_args(const string *s, ADDRINT arg0)
{
    TraceFile << *s << "(" << arg0 << ",...)" << endl;
}

/* ===================================================================== */

VOID  do_call_args_indirect(ADDRINT target, ADDRINT source, ADDRINT arg0)
{
    //if( !taken ) return;

    const string *s = Target2String(target, source);
    do_call_args(s, arg0);

    if (s != &invalid)
        delete s;
}

/* ===================================================================== */

VOID  do_call(const string *s)
{
    TraceFile << *s << endl;
}

/* ===================================================================== */


/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {

        INS tail = BBL_InsTail(bbl);
		const ADDRINT source = INS_Address(tail);
		PIN_LockClient();
		IMG currentimg = IMG_FindByAddress(source);
		PIN_UnlockClient();
		if(!IMG_Valid(currentimg) || !IMG_IsMainExecutable(currentimg)) {
			continue;
		}


        if( INS_IsCall(tail) )
        {
			/*if(IMG_Valid(currentimg)) {
				TraceFile << IMG_Name(currentimg) << ":";
			}*/
			TraceFile << std::hex << source << ":" << endl;;

            if( INS_IsDirectBranchOrCall(tail) )
            {
                const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args),
                                             IARG_PTR, Target2String(target, INS_Address(tail)), IARG_G_ARG0_CALLER, IARG_END);
            }
            else
            {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_ADDRINT, INS_Address(tail), IARG_BRANCH_TAKEN,  IARG_G_ARG0_CALLER, IARG_END);
            }
        }
        else
        {
            // sometimes code is not in an image
            RTN rtn = TRACE_Rtn(trace);
            // also track stup jumps into share libraries
            if( RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) && ".plt" == SEC_Name( RTN_Sec( rtn ) ))
            {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_G_ARG0_CALLER, IARG_END);
            }
        }

    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    TraceFile << "# eof" << endl;

    TraceFile.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int  main(int argc, char *argv[])
{

    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }


    TraceFile.open("calltrace.out");

    TraceFile << hex;
    TraceFile.setf(ios::showbase);

    string trace_header = string("#\n"
                                 "# Call Trace Generated By Pin\n"
                                 "#\n");

//TRACE_AddSmcDetectedFunction 	( 	SMC_CALLBACK  	fun, VOID *  	val )
    TraceFile.write(trace_header.c_str(),trace_header.size());

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
