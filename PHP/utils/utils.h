#include <stdio.h>
#include <iostream>
#include <fstream>
#ifdef BUILD_UTIL
#include <map>
#include <windows.h>
#include <cryptopp/gzip.h>
#include <cryptopp/hex.h>
#endif
#include <cryptopp/files.h>

#define LEVEL_INFO      0
#define LEVEL_WARNING   1
#define LEVEL_ERR       2


namespace utils {
  class Logger {
    public:
	    Logger();
      Logger(std::string &filename);
	    void open(std::string &filename);
      void close(void);
      ~Logger();
      void AddEntry(std::string line);
      void AddEvent(UINT32 level, std::string line);
      static std::string Bin2hex(unsigned char *data, UINT32 size);
      static void displaymessage(std::string message);
   private:
      std::ofstream _logfile;
#ifdef BUILD_UTIL
      LPCRITICAL_SECTION _CriticalSection = new CRITICAL_SECTION;
      CryptoPP::FileSink *_sink;
      CryptoPP::Gzip *_zipper;
#endif
  };
}

/*
  BOOL FollowChild(CHILD_PROCESS childProcess, VOID * userData)
  {
      INT Argc;
      CHAR **Argv;
      CHILD_PROCESS_GetCommandLine(childProcess, 	&pArgc, &pArgv);
      std::string cmdline(Argv[0]);
      cmdline += "(";
      for(unsigned int i=1; i<pArgc; i++) {
        if(i>1) {
          cmdline += ", ";
        }
        cmdline += Argv[i];
      }
      DebugFile << "New subprocess: " << cmdline << endl;
      return TRUE;
  }
  BOOL ThreadStarted(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
  {
      DebugFile << "New Thread: " << threadIndex << std::endl;
      return TRUE;
  }
  VOID AddFollowThreadFunction(std::ofstream &TheadTraceFile)
  {
    util_arg arg;
    arg.TraceFile = TheadTraceFile;
    PIN_AddThreadStartFunction(ThreadStarted, &arg);
  }

  VOID AddFollowThreadFunction(std::ofstream &ProcessTraceFile)
  {
    util_arg arg;
    arg.TraceFile = ProcessTraceFile;
    PIN_AddFollowChildProcessFunction(FollowChild, &arg);
  }
};
*/
