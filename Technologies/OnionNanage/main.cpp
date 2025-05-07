#include "OnionManager.h"


int main()
{
    Node* a = new Node();

    OnionManager* manage = new OnionManager();
    std::vector<uint8_t> vec = {'s', 's', 's'};
    a->public_Key = manage->GetPublicKey();
    vec = manage->EncryptWithPublicKey(*a, vec);

    // Print the contents of vec
    std::cout << "Encrypted vector contents: ";
    for (uint8_t byte : vec)
    {
        std::cout << static_cast<int>(byte) << " "; // Print as integers
    }
    std::cout << std::endl;

    delete a;
    delete manage;

    return 0;
}