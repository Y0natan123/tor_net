#include "ErrorHandling.h"

// טיפול בשגיאה כללית
void ErrorHandling::HandleError(const std::string& errorMessage) {
    std::cout << "Error: " << errorMessage << std::endl;
    // לוגיקת טיפול בשגיאות
}

// טיפול בשגיאת הצפנה
void ErrorHandling::HandleEncryptionError(const std::string& errorMessage) {
    std::cout << "Encryption Error: " << errorMessage << std::endl;
    // לוגיקת טיפול בשגיאות הצפנה, כגון ניסיון הצפנה חוזר או הפסקת תהליך
}

// טיפול בשגיאת חבילה פגומה
void ErrorHandling::HandlePacketError(const std::string& errorMessage) {
    std::cout << "Packet Error: " << errorMessage << std::endl;
    // לוגיקת טיפול בשגיאות חבילות, כמו ניסיון לשלוח חבילה שוב או תיקון החבילה
}

// טיפול בשגיאת תקשורת
void ErrorHandling::HandleCommunicationError(const std::string& errorMessage) {
    std::cout << "Communication Error: " << errorMessage << std::endl;
    // לוגיקת טיפול בשגיאות תקשורת, כגון בדיקת תקינות חיבור
}

// הדפסת הודעת שגיאה כללית
void ErrorHandling::PrintError(const std::string& errorMessage) {
    std::cout << "Error: " << errorMessage << std::endl;
}
