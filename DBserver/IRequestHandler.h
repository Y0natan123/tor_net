#ifndef IREQUESTHANDLER
#define IREQUESTHANDLER
#include <iostream>
#include <string.h>
#include <vector>
#include <map>
#include <ctime>

#define LoginReq 205
#define SignReq 206
#define confirmationAESKey 79
#define GetKeysReq 207
#define GetBigKeysReq 208
#define DirecReq 209
#define PortReq 210
#define getAESKeyReq 211
#define NODE_TO_NODE 212
#define ErorReq 100
#define Signout 101
#include "AES.h"


class IRequestHandler;
struct RequestResult
{
	IRequestHandler* newHandler;
	std::vector<unsigned char> response;

}typedef  RequestResult;

struct RequestInfo
{
	int RequestId = 0;
	time_t receivalTime;
	std::vector<unsigned char> buffer;

}typedef RequestInfo;

class IRequestHandler
{
public:
	
	static RequestInfo makeInfo(std::vector<unsigned char> req);
};

#endif 