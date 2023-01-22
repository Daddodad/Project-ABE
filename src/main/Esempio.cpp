#include "abecontext.h"
#include "cpabe.h"
#include "abecore.h"
#include <cmath>
#include <memory>
#include <vector>

/*
#include "encoding/plaintextfactory.h"
#include "lattice/elemparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/ilparams.h"
#include "lattice/trapdoorparameters.h"
#include "math/backend.h"
#include "math/distrgen.h"
#include "utils/inttypes.h"
*/

#include <iostream>
#include <fstream>
#include <string>


using namespace lbcrypto;
//using namespace std;

int main() {
    usint a;
    int b;
    a=-1;
    b=-1;
    std::cout << "a:" << a << std::endl;
    std::cout << "b:" << b << std::endl;

    unsigned int ringsize=1024; //dimensione dello spazio?
    unsigned int base=64; //boh
    unsigned int numAttributi=6; //questo è chiaro
    ABEContext<NativePoly> contesto; //creo la variabile contesto
    contesto.GenerateCPABEContext(numAttributi, ringsize, base);

    std::cout << "Genero master secret key e master public key" << std::endl;
    // Generate master keys

    CPABEMasterPublicKey<NativePoly> mpk;
    CPABEMasterSecretKey<NativePoly> msk;

    contesto.Setup(&mpk, &msk);

    // Lettura da file della Access Policy
    std::vector<int> w(6);

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
    std::vector<usint> s(6);

    file.open("../src/files//User_Attribute_List.txt", std::ios::in);
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


return 0;
}
