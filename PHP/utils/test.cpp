#include "utils.h"

int main(void)
{
  std::string filename("log.gzip");
  utils::Logger mylogger(filename);
  mylogger.AddEntry("test");
  return 0;
}
