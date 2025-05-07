
#ifndef IDATABASE_H
#define IDATABASE_H

#include <list>
#include <map>
#include <string>

class IDatabase
{
public:
    virtual int doesUserExist(std::string username) = 0;
    virtual bool open() = 0;
    virtual void close() = 0;
    virtual void clear() = 0;
};

#endif // IDATABASE_H
