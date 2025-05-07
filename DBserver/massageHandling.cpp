#include "massageHandling.h"



massageHandling::massageHandling(/* args */)
{
}

massageHandling::~massageHandling()
{
}


void massageHandling::WriteToFileWithLock(const std::string& filename, const std::string& text, int retryIntervalMs) 
{
    while (true) {
        std::ofstream file(filename, std::ios::app);  // ניסיון לפתוח את הקובץ במצב הוספה
        if (file.is_open()) {
            file << text << std::endl;
            file.close();
            std::cout << "Successfully wrote to the file: " << filename << std::endl;
            return;
        } else {
            std::cout << "File is locked. Retrying in " << retryIntervalMs << "ms..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(retryIntervalMs));
        }
    }
}



std::string massageHandling::ReadFromFileWithLock(const std::string& filename, int retryIntervalMs, int emptyFileWaitMs ) {
    while (true) {
        std::ifstream file(filename);
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            if (content.empty()) {
                std::cout << "File is empty. Waiting " << emptyFileWaitMs << "ms before retrying..." << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(emptyFileWaitMs));
                continue;  // מחכה ומנסה שוב
            }

            // ניקוי הקובץ אחרי קריאה מוצלחת
            std::ofstream clearFile(filename, std::ofstream::trunc);
            clearFile.close();

            std::cout << "Successfully read from file: " << content << std::endl;
            return content;
        } else {
            std::cout << "File is locked. Retrying in " << retryIntervalMs << "ms..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(retryIntervalMs));
        }
    }
}