#include <iostream>
#include "IDatabase.h"
#include "sqlite3.h"

#include <map>
#include <vector>
#include "JsonResponsePacketSerializer.h"
#define SQLITE_OK 0   /* Successful result */


class SqliteDatabase 
{
public:
	SqliteDatabase();
	~SqliteDatabase();
	bool open() ;
	bool openNodes() ;
	bool openIdDb();
	std::pair<uint64_t, uint64_t> findPublicKeyByIpAndPort(const std::string& ip, int port);
	bool insertNode(const std::string& ip, int port, const std::pair<uint64_t, uint64_t>& publicKey);
	bool deleteNode(const std::string& ip, int port);
	void close() ;
	void clear();
	int generateUniqueId();

	GetKeysResponse getAllNodesWithKeys();
	GetKeysResponse getAllNodesWithKeys(const std::string& requestedIP, int requestedPort);


private:
	sqlite3* _idDb;
	std::string _idDbFileName = "";
	sqlite3* _db;
	std::string _dbFileName = "";
};
