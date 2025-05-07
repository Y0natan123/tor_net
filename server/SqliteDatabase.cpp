#include "SqliteDatabase.h"

#include <random>
#include <sstream>

SqliteDatabase::SqliteDatabase()
{
    _dbFileName = "KysDB.sqlite";
    _idDbFileName = "IdDB.sqlite";
    open();
    clear();
}

SqliteDatabase::~SqliteDatabase()
{
    close();
}
bool SqliteDatabase::open()
{
    openNodes();
    openIdDb();
    return true;

}
bool SqliteDatabase::openNodes()
{
	clear();
    int res = sqlite3_open(_dbFileName.c_str(), &_db);

    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(_db) << std::endl;
        return false;
    }

    const char* createNodesTable =
        "CREATE TABLE IF NOT EXISTS NODES("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "IP TEXT NOT NULL,"
        "PORT INTEGER NOT NULL,"
        "PUBLIC_AES_KEY_FIRST INTEGER NOT NULL,"
        "PUBLIC_AES_KEY_SECOND INTEGER NOT NULL"
        ");";


    res = sqlite3_exec(_db, createNodesTable, nullptr, nullptr, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to create table: " << sqlite3_errmsg(_db) << std::endl;
        return false;
    }

    return true;
}

bool SqliteDatabase::openIdDb()
{
    int res = sqlite3_open(_idDbFileName.c_str(), &_idDb);

    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to open ID database: " << sqlite3_errmsg(_idDb) << std::endl;
        return false;
    }

	const char* createIdsTable =
    	"CREATE TABLE IF NOT EXISTS IDS("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT"
    ");";


    res = sqlite3_exec(_idDb, createIdsTable, nullptr, nullptr, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to create ID table: " << sqlite3_errmsg(_idDb) << std::endl;
        return false;
    }

    return true;
}


GetKeysResponse SqliteDatabase::getAllNodesWithKeys()
{
    GetKeysResponse response;
    sqlite3_stmt* stmt = nullptr;

    // SQL query to select all columns from the NODES table
    const char* query = "SELECT IP, PORT, PUBLIC_AES_KEY_FIRST, PUBLIC_AES_KEY_SECOND FROM NODES;";

    int res = sqlite3_prepare_v2(_db, query, -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(_db) << std::endl;
        return response;
    }

    close();
    open();

    // Loop through the results
    while ((res = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        // Retrieve IP
        const char* ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        // Retrieve PORT
        int port = sqlite3_column_int(stmt, 1);
        // Retrieve PUBLIC_AES_KEY_FIRST and PUBLIC_AES_KEY_SECOND
        uint64_t publicKeyFirst = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
        uint64_t publicKeySecond = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));

        // Create a public key pair
        std::pair<uint64_t, uint64_t> publicKey(publicKeyFirst, publicKeySecond);

        // Create a node struct
        Node currentNode = { std::string(ip), port, publicKey };

        // Add the node to the response
        response.m_public_Keys.push_back(currentNode);
    }

    if (res != SQLITE_DONE)
    {
        std::cerr << "Error reading from database: " << sqlite3_errmsg(_db) << std::endl;
    }


    sqlite3_finalize(stmt);

    // Generate a unique ID and ensure it's not in the IDS database
    response.id = generateUniqueId();

    return response;
}

int SqliteDatabase::generateUniqueId()
{
    sqlite3_stmt* stmt = nullptr;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(1, 1000000);

    int uniqueId;
    bool isUnique = false;

    while (!isUnique)
    {
        uniqueId = dis(gen);

        const char* query = "SELECT COUNT(*) FROM IDS WHERE ID = ?;";
        int res = sqlite3_prepare_v2(_idDb, query, -1, &stmt, nullptr);
        if (res != SQLITE_OK)
        {
            std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(_idDb) << std::endl;
            break;
        }

        close();
        open();
        sqlite3_bind_int(stmt, 1, uniqueId);

        res = sqlite3_step(stmt);
        if (res == SQLITE_ROW)
        {
            int count = sqlite3_column_int(stmt, 0);
            isUnique = (count == 0);
        }

        sqlite3_finalize(stmt);
    }

    // Insert the unique ID into the IDS table
    const char* insertQuery = "INSERT INTO IDS (ID) VALUES (?);";
    int res = sqlite3_prepare_v2(_idDb, insertQuery, -1, &stmt, nullptr);
    if (res == SQLITE_OK)
    {

        close();
        open();
        sqlite3_bind_int(stmt, 1, uniqueId);
        res = sqlite3_step(stmt);
        if (res != SQLITE_DONE)
        {
            std::cerr << "Error inserting ID: " << sqlite3_errmsg(_idDb) << std::endl;
        }
        sqlite3_finalize(stmt);
    }
    else
    {
        std::cerr << "Failed to prepare insert statement: " << sqlite3_errmsg(_idDb) << std::endl;
    }

    return uniqueId;
}
std::pair<uint64_t, uint64_t> SqliteDatabase::findPublicKeyByIpAndPort(const std::string& ip, int port)
{
    std::pair<uint64_t, uint64_t> publicKey = {0, 0};
    sqlite3_stmt* stmt = nullptr;

    // SQL query to select the public key parts by IP and PORT
    const char* query = "SELECT PUBLIC_AES_KEY_FIRST, PUBLIC_AES_KEY_SECOND FROM NODES WHERE IP = ? AND PORT = ?;";

    int res = sqlite3_prepare_v2(_db, query, -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(_db) << std::endl;
        return publicKey;
    }

    close();
    open();

    // Bind IP and PORT to the prepared statement
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, port);

    // Execute the query
    res = sqlite3_step(stmt);
    if (res == SQLITE_ROW)
    {
        // Retrieve the PUBLIC_AES_KEY_FIRST and PUBLIC_AES_KEY_SECOND values
        publicKey.first = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
        publicKey.second = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
    }
    else if (res == SQLITE_DONE)
    {
        std::cout << "No record found for IP: " << ip << " and PORT: " << port << std::endl;
    }
    else
    {
        std::cerr << "Error executing query: " << sqlite3_errmsg(_db) << std::endl;
    }

    // Clean up
    sqlite3_finalize(stmt);

    return publicKey;
}


bool SqliteDatabase::insertNode(const std::string& ip, int port, const std::pair<uint64_t, uint64_t>& publicKey)
{
    sqlite3_stmt* stmt = nullptr;

    // SQL query to insert a new node
    const char* query = "INSERT INTO NODES (IP, PORT, PUBLIC_AES_KEY_FIRST, PUBLIC_AES_KEY_SECOND) VALUES (?, ?, ?, ?);";

    int res = sqlite3_prepare_v2(_db, query, -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(_db) << std::endl;
        return false;
    }

    close();
    open();

    // Bind IP and PORT
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, port);

    // Bind the first and second parts of the public key as 64-bit integers
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(publicKey.first));
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(publicKey.second));

    // Execute the query
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        std::cerr << "Error inserting node: " << sqlite3_errmsg(_db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    // Clean up
    sqlite3_finalize(stmt);
    return true;
}


bool SqliteDatabase::deleteNode(const std::string& ip, int port)
{
	sqlite3_stmt* stmt = nullptr;

	// SQL query to delete a node based on IP and PORT
	const char* query = "DELETE FROM NODES WHERE IP = ? AND PORT = ?;";

	// Prepare the statement
	int res = sqlite3_prepare_v2(_db, query, -1, &stmt, nullptr);
	if (res != SQLITE_OK)
	{
		std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(_db) << std::endl;
		return false;
	}

	// Bind IP and PORT
	sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, port);

	// Execute the query
	res = sqlite3_step(stmt);
	if (res != SQLITE_DONE)
	{
		std::cerr << "Error deleting node: " << sqlite3_errmsg(_db) << std::endl;
		sqlite3_finalize(stmt);
		return false;
	}

	// Clean up
	sqlite3_finalize(stmt);
	return true;
}

void SqliteDatabase::clear()
{
    const char* clearNodesQuery = "DELETE FROM NODES;";
    sqlite3_stmt* stmt = nullptr;

    // Clear the NODES table
    int res = sqlite3_prepare_v2(_db, clearNodesQuery, -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to prepare clear statement for NODES table: " << sqlite3_errmsg(_db) << std::endl;
        return;
    }

    close();
    open();

    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        std::cerr << "Error clearing NODES table: " << sqlite3_errmsg(_db) << std::endl;
    }

    sqlite3_finalize(stmt);

    // Clear the IDS table
    const char* clearIdsQuery = "DELETE FROM IDS;";
    res = sqlite3_prepare_v2(_idDb, clearIdsQuery, -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to prepare clear statement for IDS table: " << sqlite3_errmsg(_db) << std::endl;
        return;
    }

    close();
    open();

    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        std::cerr << "Error clearing IDS table: " << sqlite3_errmsg(_db) << std::endl;
    }

    sqlite3_finalize(stmt);
}



void SqliteDatabase::close()
{
    if (_db)
    {
        sqlite3_close(_db);
        _db = nullptr;
    }

    if (_idDb)
    {
        sqlite3_close(_idDb);
        _idDb = nullptr;
    }
}
