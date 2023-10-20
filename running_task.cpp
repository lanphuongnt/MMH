//C internal library 
#include <iostream>
using std::wcin;
using std::wcout;
using std::wcerr;
using std::endl;
using std::cout;
using std::cin;

#include <string>
using std::string;
using std::wstring;
#include <cstdlib>
using std::exit;
#include "assert.h"
#include "fstream"


//Cryptopp Librari
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

// convert string
// Hex <---> Binary
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// Base64 <---> Binary
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

// Block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;
#include "cryptopp/aes.h"
using CryptoPP::AES;

//Mode of operations
#include "cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include <cryptopp/ccm.h>
using CryptoPP::CCM;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
//Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison


/* Set utf8 support for windows*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string <--> utf8*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

using namespace std;
using namespace CryptoPP;

#include "convert.h"
#include "userio.h"
#include "AES_Cipher.h"
#include "running_task.h"

void full_option()
{
    #ifdef __linux__
    setlocale(LC_ALL, "");
    #elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    #endif

    // CryptoPP::byte meo[16] = {0x00, 0x01, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    
    string mode, userSelection, plaintext, ciphertext;
    modeSelection(mode);
    userSelection = selectEncryptOrDecrypt();
    AES_Cipher aes(mode);
    if (userSelection == "encrypt"){
        inputPlaintextSelection(plaintext);
        ciphertext = aes.encrypt(plaintext);
        outputSelection(ciphertext, false, true);
    }
    else {
        ciphertext = inputCiphertextSelection();
        plaintext = aes.decrypt(ciphertext);
        outputSelection(plaintext, true, false);
    }
    wcout << "SUMMARISE:\n"
            << "MODE : " << string_to_wstring(mode) << '\n'
            << "KEY : " << string_to_wstring(hexencode(aes.key, aes.keySize)) << '\n';
    if (mode != "ECB"){
        wcout << "IV/CTR : " << string_to_wstring(hexencode(aes.iv, aes.ivSize)) << '\n';
    }
    wcout << "LENGTH OF PLAINTEXT : " << plaintext.size() << '\n'
          << "LENGTH OF CIPHERTEXT : " << ciphertext.size() << '\n';
}
