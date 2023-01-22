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

using namespace lbcrypto;
int main() {


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

std::cout << mpk.GetA().ExtractCol(0);

NativePoly pippo=contesto.GenerateRandomElement();
NativePoly franco;
//std::cout << pippo[0];
//std::cout << pippo.SwitchFormat();

    //size_t rows=5;
    //size_t cols=5;
    Matrix<NativePoly> test;
    std::cout << test.SerializedObjectName();
    //auto zero_alloc = NativePoly::Allocator(5, Format::EVALUATION);
    //test.Matrix();

    //test.SetSize(rows,cols);
    
std::fstream my_file;
my_file.open("../src/files/A2.txt", std::ios::out);
    //size_t zero=1;
	if (!my_file) {
		std::cout << "File not created!\n";
	}
	else {
		std::cout << "File created successfully!\n";    
        my_file << test;
		my_file.close(); 
}
//test=mpk.GetA();
//test.HStack(mpk.GetA().ExtractCol(zero));
    
    //std::fstream my_file;
    my_file.open("../src/files/A2", std::ios::in);
    if (!my_file) {
		std::cout << "File not opened!\n";
	}
	else {
		std::cout << "File opened successfully!\n";
        //my_file >> franco;
		my_file.close(); 
	}

return 0;
}