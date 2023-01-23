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

    CPABEMasterPublicKeyZZG<NativePoly> mpk;
    CPABEMasterSecretKeyZZG<NativePoly> msk;

    usint d=3;
    context.Setup(d,&mpk, &msk);
    
    
return 0;
}
