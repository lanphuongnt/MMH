#include "AES_Cipher.h"
#include "running_task.h"
#include "convert.h"
#include "userio.h"
#include "block_time_running.h"

using namespace std;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

int main(){
    #ifdef _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    #endif
    // full_option();
    block_time_running();
    return 0;
}