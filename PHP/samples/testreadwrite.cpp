#include <windows.h>
#include <stdio.h>

int main(void)
{
  char buffer[2048] = {0};
  for(unsigned int i=0;i<sizeof(buffer); i++) {
    buffer[i] = 'A';
  }
  printf("%s\n", buffer);
  return 0;
}
