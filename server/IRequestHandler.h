#include <iostream>
#include <string.h>
#include <vector>
#include <map>
#include <ctime>

#include "Sink.h"
#include "JsonResponsePacketDeserializer.h"



#define LoginReq 205
#define SignReq 206
#define GetKeysReq 207
#define GetSpecificKeyReq 211  // New request type
#define ErorReq 100
#define Signout 101



class IRequestHandler;


struct RequestInfo
{
	int RequestId = 0;
	time_t receivalTime;
	std::vector<unsigned char> buffer;

}typedef RequestInfo;

class IRequestHandler
{
private:

public:
	
	static RequestInfo  makeInfo(std::vector<unsigned char> req);
	int handleRequest(RequestInfo reqinfo) ;
	SignupRequest handleSignRequest(RequestInfo reqinfo);

};

