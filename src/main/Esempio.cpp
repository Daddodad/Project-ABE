#include "abecontext.h"
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

    //ABEContext<NativePoly> contesto;
    contesto.Stampa_ciao();
    contesto.Stampa_cia();
    std::cout << "b:" << b << std::endl;
return 0;
}
