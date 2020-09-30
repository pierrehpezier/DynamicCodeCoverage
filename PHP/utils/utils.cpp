#include "utils.h"


std::map<UINT32, std::string> logmap = {
      {LEVEL_INFO, "INFO"},
      {LEVEL_WARNING, "WARNING"},
      {LEVEL_ERR, "ERROR"},
};

utils::Logger::Logger(std::string &filename)
{
    InitializeCriticalSection(_CriticalSection);
    open(filename);
}

utils::Logger::Logger()
{
    InitializeCriticalSection(_CriticalSection);
}

void utils::Logger::close(void)
{
  _zipper->MessageEnd();
  _logfile.close();
}

utils::Logger::~Logger()
{
  close();
  DeleteCriticalSection(_CriticalSection);
}

void utils::Logger::displaymessage(std::string message)
{
  typedef int (WINAPI *_mymessagebox)(HWND, LPCTSTR, LPCTSTR, UINT);
  _mymessagebox mymessagebox = (_mymessagebox)GetProcAddress(LoadLibrary("user32.dll"), "MessageBoxA");
  mymessagebox(0, message.c_str(), "PIN DEBUGGER", 0);
}

void utils::Logger::AddEvent(UINT32 level, std::string line)
{
  std::string entry = logmap[level] + std::string(";") + line;
  AddEntry(entry);
}

std::string utils::Logger::Bin2hex(unsigned char *data, UINT32 size)
{
  std::string encoded;
  CryptoPP::HexEncoder encoder;
  encoder.Put((const byte*)data, size);
  encoder.MessageEnd();
  size_t encodedsize = encoder.MaxRetrievable();
  if(!encodedsize)
    return "";
  encoded.resize(encodedsize);
  encoder.Get((byte*)&encoded[0], encodedsize);
  return encoded;
}

void utils::Logger::open(std::string &filename)
{
  _logfile.open(filename);
  _sink = new CryptoPP::FileSink(filename.c_str(), true);
  _zipper = new CryptoPP::Gzip(_sink);
}

void utils::Logger::AddEntry(std::string line)
{
  EnterCriticalSection(_CriticalSection);
  _zipper->Put((BYTE *)line.c_str(), line.length());
  _zipper->Put((BYTE *)"\n", 1);
  LeaveCriticalSection(_CriticalSection);
}
