#include "IRequestHandler.h"
#include <cstring> // Include this header for memcpy



/**
 * Constructs a RequestInfo object from a vector of unsigned characters.
 *
 * parameter: req A vector of unsigned characters representing a request.
 * return: RequestInfo An object containing information extracted from the input vector.
 */
RequestInfo IRequestHandler::makeInfo(std::vector<unsigned char> req)
{
	time_t now;
	uint32_t length = 0;
	RequestInfo ret;
	int sizeMsg = 0;
	unsigned char arr[4] = {0};
	unsigned int result = 0;
	ret.receivalTime;
	ret.RequestId = int(req[0]);
	now = time(nullptr);
	ret.receivalTime = now;



	for (int i = 0; i < 4; ++i) 
	{
		arr[i] = req[i+1];
	}
	std::memcpy(&length, arr, sizeof(result)); // Remove std:: prefix




	for (size_t i = 5; i < length+5; i++)
	{
		ret.buffer.push_back(req[i]);
	}
	return ret;
}

