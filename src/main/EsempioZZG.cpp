#include "abecontext.h"
#include "cpabe.h"
#include "abecore.h"
#include <cmath>
#include <memory>
#include <vector>
#include <iostream>
#include <fstream>
#include <string>

#include "../lib/abecontextzzg.h"

using namespace lbcrypto;
using namespace std;

int main() {

    ABEContextZZG<NativePoly> context;

    std::cout << context.StampaCiao(3) << std::endl;
    context.Setj(3);
    std::cout << context.Getj()<< std::endl;

    usint ringsize=1024; //dimensione dello spazio? buffer
    usint base=64; //boh
    usint numAttributi=6; //questo è chiaro
    context.GenerateCPABEContextZZG(numAttributi, ringsize, base);

    CPABEMasterPublicKeyZZG<NativePoly> mpkZZG;
    CPABEMasterSecretKeyZZG<NativePoly> mskZZG;

	shared_ptr<ABECoreParams<NativePoly>> parameters;
	context.ParamsGenCPABEZZG(ringsize, numAttributi, base, parameters);
	
    usint d=4;
    context.Setd(d);
    context.Setup(parameters,&mpkZZG, &mskZZG);

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
    CPABESecretKey<NativePoly> sk; //utilizziamo lo stesso perchè sono entrambe matrici.

    // Genero tale chiave usando il metodo della classe ABEContextZZG
    context.KeyGenZZG(parameters, mpkZZG, mskZZG, ua, &sk);

return 0;
}
