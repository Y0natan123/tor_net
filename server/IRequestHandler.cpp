#include "IRequestHandler.h"



/**
 * Constructs a RequestInfo object from a vector of unsigned characters.
 *
 * parameter: req A vector of unsigned characters representing a request.
 * return: RequestInfo An object containing information extracted from the input vector.
 */
RequestInfo IRequestHandler::makeInfo(std::vector<unsigned char> req)
{
	std::vector<unsigned char> sizeInBytes ; // Little-endian representation of 0x12345678
	time_t now ;
	uint32_t length = 0;
	RequestInfo ret;
	int sizeMsg = 0;
	unsigned char arr[4] = {0};
	unsigned int result = 0;
	ret.receivalTime;
	ret.RequestId = int(req[0]);
	now = time(nullptr);
	ret.receivalTime = now;



	for (int i = 0; i < 4; ++i) {
		arr[i] = req[i+1];
	}
	std::memcpy(&length, arr, sizeof(result));



	for (size_t i = 5; i < length+5; i++)
	{
		ret.buffer.push_back(req[i]);
	}
	return ret;
}

int IRequestHandler::handleRequest(RequestInfo reqinfo)
{
	int result;

	SignupRequest signupReq;
	switch (reqinfo.RequestId)
	{
	case 206:
		result = 206;
		break;
	case 207:
		result = 207;
		break;
	case 208:
		result = 208;
		break;
	case 211:  // New case for specific key request
		result = 211;
		break;
	case 3:
		break;
	case 4:
		break;
	case 5:
		break;
	case 6:
		break;
	default:
		break;
	}
	
	return result;
}

SignupRequest IRequestHandler::handleSignRequest(RequestInfo reqinfo)
{
	JsonResponsePacketDeserializer deserializer;
	SignupRequest signupReq;
	signupReq = deserializer.deserializeSignupRequest(reqinfo.buffer);
	return signupReq;
}

