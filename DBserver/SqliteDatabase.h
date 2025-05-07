
#include <iostream>
#include "IDatabase.h"
#include "sqlite3.h"
#include "AES.h"
#include <map>
#include <vector>
#include "JsonResponsePacketSerializer.h"
#define SQLITE_OK 0   /* Successful result */

class SqliteDatabase 
{
public:
    SqliteDatabase();
    ~SqliteDatabase();


    bool open();


    std::pair<std::vector<uint8_t>, std::array<uint8_t, BLOCK_SIZE>> getKey(int id);

    bool insertKey(const std::pair<std::vector<uint8_t>, std::array<uint8_t, BLOCK_SIZE>>& dataPair, int ID);


    bool deleteKey(int id);

    void close();


    void clear();

private:
    sqlite3* _db;               // SQLite database connection
    std::string _dbFileName = ""; // Database file name
};



