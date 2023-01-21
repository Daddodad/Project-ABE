#include "abecontext.h"
#include "cpabe.h"
#include "abecore.h"
#include <cmath>
#include <memory>
#include <vector>

#include "encoding/plaintextfactory.h"
#include "lattice/elemparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/ilparams.h"
#include "lattice/trapdoorparameters.h"
#include "math/backend.h"
#include "math/distrgen.h"
#include "utils/inttypes.h"

#include <iostream>
#include <fstream>
#include <string>


using namespace lbcrypto;

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

    Matrix<NativePoly> test;

    contesto.Setup(&mpk, &msk);

    std::vector<usint> attributi(6);
    std::vector<int> access_policy(6);

std::ifstream f;
f.open("Access_Policy.txt");
std::string my_string;

f >> my_string;
    std::cout << "ddd" << my_string << std::endl;

    //ofstream out("out.txt")

    //test=mpk.GetA();
    //std::cout << test << std::endl;

return 0;
}
