#include "SqliteDatabase.h"
#include <sstream>



SqliteDatabase::SqliteDatabase()
{
	_dbFileName = "Keys.sqlite";
	open();
    clear();
}

SqliteDatabase::~SqliteDatabase()
{
    close();
}

bool SqliteDatabase::open()
{
    int res = sqlite3_open(_dbFileName.c_str(), &_db);

    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(_db) << std::endl;
        return false;
    }

    // SQL statement to create a table for IP, PORT, and public AES key (split into two integers)
    const char* createNodesTable =
    "CREATE TABLE IF NOT EXISTS NODES("
    "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
    "PUBLIC_AES_KEY_FIRST BLOB NOT NULL,"
    "SECOND_ARRAY BLOB NOT NULL"
    ");";


    res = sqlite3_exec(_db, createNodesTable, nullptr, nullptr, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to create table: " << sqlite3_errmsg(_db) << std::endl;
        return false;
    }

    return true;
}
std::pair< std::vector<uint8_t>,std::array<uint8_t, BLOCK_SIZE>> SqliteDatabase::getKey(int id)
{
    std::vector<uint8_t> publicKey;
    std::array<uint8_t, BLOCK_SIZE> secondArray;
    sqlite3_stmt* stmt = nullptr;
    std::pair< std::vector<uint8_t>,std::array<uint8_t, BLOCK_SIZE>> AESkeys;

    // SQL query to retrieve both parts of the pair
    const char* query = "SELECT PUBLIC_AES_KEY_FIRST, SECOND_ARRAY FROM NODES WHERE ID = ?;";

    int res = sqlite3_prepare_v2(_db, query, -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(_db) << std::endl;
        return AESkeys;
    }

    // Bind the ID to the query
    sqlite3_bind_int(stmt, 1, id);

    // Execute the query
    res = sqlite3_step(stmt);
    if (res == SQLITE_ROW)
    {
        // Retrieve the BLOBs for the first part and the second array
        const void* blob1 = sqlite3_column_blob(stmt, 0);
        int blob1Size = sqlite3_column_bytes(stmt, 0);
        const void* blob2 = sqlite3_column_blob(stmt, 1);
        int blob2Size = sqlite3_column_bytes(stmt, 1);

        if (blob1 && blob1Size > 0)
        {
            publicKey.assign(static_cast<const uint8_t*>(blob1), static_cast<const uint8_t*>(blob1) + blob1Size);
        }

        if (blob2 && blob2Size == BLOCK_SIZE)
        {
            std::memcpy(secondArray.data(), blob2, BLOCK_SIZE);
        }
    }
    else if (res != SQLITE_DONE)
    {
        std::cerr << "Error retrieving key: " << sqlite3_errmsg(_db) << std::endl;
    }

    // Clean up
    sqlite3_finalize(stmt);

    // Store the retrieved pair
    AESkeys = std::make_pair(publicKey, secondArray);
    return AESkeys;
}


bool SqliteDatabase::insertKey(const std::pair<std::vector<uint8_t>, std::array<uint8_t, BLOCK_SIZE>>& dataPair, int ID)
{
    sqlite3_stmt* stmt = nullptr;

    // SQL query to insert or replace a key with a specific ID
    const char* query = "INSERT OR REPLACE INTO NODES (ID, PUBLIC_AES_KEY_FIRST, SECOND_ARRAY) VALUES (?, ?, ?);";

    int res = sqlite3_prepare_v2(_db, query, -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(_db) << std::endl;
        return false;
    }

    // Bind the ID
    res = sqlite3_bind_int(stmt, 1, ID);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to bind ID: " << sqlite3_errmsg(_db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    // Bind the public key as BLOB
    res = sqlite3_bind_blob(stmt, 2, dataPair.first.data(), static_cast<int>(dataPair.first.size()), SQLITE_STATIC);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to bind public key: " << sqlite3_errmsg(_db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    // Bind the second array as BLOB
    res = sqlite3_bind_blob(stmt, 3, dataPair.second.data(), BLOCK_SIZE, SQLITE_STATIC);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to bind second array: " << sqlite3_errmsg(_db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    // Execute the query
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        std::cerr << "Error inserting or replacing key: " << sqlite3_errmsg(_db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    // Clean up
    sqlite3_finalize(stmt);
    return true;
}

bool SqliteDatabase::deleteKey(int id)
{
    sqlite3_stmt* stmt = nullptr;

    // SQL query to delete a key based on its ID
    const char* query = "DELETE FROM NODES WHERE ID = ?;";

    // Prepare the statement
    int res = sqlite3_prepare_v2(_db, query, -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(_db) << std::endl;
        return false;
    }

    // Bind the ID to the query
    sqlite3_bind_int(stmt, 1, id);

    // Execute the query
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        std::cerr << "Error deleting key: " << sqlite3_errmsg(_db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    // Clean up
    sqlite3_finalize(stmt);
    return true;
}



void SqliteDatabase::close()
{
	sqlite3_close(_db);
	_db = nullptr;
}

void SqliteDatabase::clear()
{
    sqlite3_stmt* stmt = nullptr;

    // SQL query to delete all rows from the table
    const char* query = "DELETE FROM NODES;";

    // Prepare the SQL statement
    int res = sqlite3_prepare_v2(_db, query, -1, &stmt, nullptr);
    if (res != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(_db) << std::endl;
        return;
    }
    close();
    open();
    // Execute the query
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE)
    {
        std::cerr << "Error clearing table: " << sqlite3_errmsg(_db) << std::endl;
    }
    else
    {
        std::cout << "Table cleared successfully." << std::endl;
    }

    // Clean up
    sqlite3_finalize(stmt);
}

