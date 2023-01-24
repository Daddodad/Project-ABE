#include <cmath>
#include <memory>
#include <vector>
#include <abecontext.h>


using namespace lbcrypto;
//using namespace std;

int main() {

    usint a;
    int b;
    a=-1;
    b=-1;
    std::cout << "a:" << a << std::endl;
    std::cout << "b:" << b << std::endl;

    usint ringsize=1024; //dimensione dello spazio? buffer
    usint base=64; //boh
    usint numAttributi=6; //questo è chiaro

    ABEContext<NativePoly> context; //creo la variabile context
    context.GenerateCPABEContext(numAttributi, ringsize, base);

    std::cout << "Genero master secret key e master public key" << std::endl;
    // Generate master keys

    CPABEMasterPublicKey<NativePoly> mpk;
    CPABEMasterSecretKey<NativePoly> msk;

    context.Setup(&mpk, &msk);

    // Lettura da file della Access Policy
    std::vector<int> w(numAttributi);

    std::fstream file;
    file.open("../src/files/Access_Policy.txt", std::ios::in);
    if (!file) {
		std::cout << "File not opened!";
	}
    else {
        int i=0;
        while (file.good()) {
            file >> w[i];
            i++;
        }
        std::cout << "w: " << w << std::endl;
        file.close();
    }

    // Lettura da file della Attribute List
    std::vector<usint> s(numAttributi);

    file.open("../src/files/User_Attribute_List.txt", std::ios::in);
    if (!file) {
		std::cout << "File not opened!";
	}
    else {
        int i=0;
        while (file.good()) {
            file >> s[i];
            i++;
        }
        std::cout << "s: " << s << std::endl;
        file.close();
    }

    // Carico le informazioni di Access Policy e User Attribute List su delle classi apposite 
    CPABEUserAccess<NativePoly> ua(s);
    CPABEAccessPolicy<NativePoly> ap(w);

    // Creiamo l'oggetto corrispondente alla key associata a tale access policy
    CPABESecretKey<NativePoly> sk;

    // Genero tale chiave usando il metodo della classe ABEContext
    context.KeyGen(msk, mpk, ua, &sk);

    // Leggo un plaintext da file
    std::vector<int64_t> vectorOfInts;
    file.open("../src/files//Plaintext_01.txt", std::ios::in);
    if (!file) {
		std::cout << "File not opened!";
	}
    else {
        int i;
        while(file >> i)
            vectorOfInts.push_back(i);
        std::cout << "Plaintext: " << vectorOfInts << std::endl;
        file.close();
    }
    //trasformo il vettore di bit in una variabile plaintext
    Plaintext pt = context.MakeCoefPackedPlaintext(vectorOfInts);

    // Encrypt the plaintext
    std::cout << "Codifico il plaintext sotto la Access Policy" << std::endl;
    
    // creo una variabile ciphertext dove andare a salvare il ct 
    CPABECiphertext<NativePoly> ct;

    // Genero il ciphertext
    context.Encrypt(mpk, ap, pt, &ct);

    // Decrypt the ciphertext
    std::cout << "Decritto il ciphertext" << std::endl;
    Plaintext dt = context.Decrypt(ap, ua, sk, ct);
    std::cout << "test";
    std::cout << "Il Plaintext è" << dt->GetElement<NativePoly>() << "\n";





    


return 0;
}
