#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>

class massageHandling
{
private:

public:
    massageHandling(/* args */);
    ~massageHandling();
    void WriteToFileWithLock(const std::string& filename, const std::string& text, int retryIntervalMs = 500);
    std::string ReadFromFileWithLock(const std::string& filename, int retryIntervalMs = 500, int emptyFileWaitMs = 4000);


};

