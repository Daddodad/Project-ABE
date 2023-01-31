#include "abecontext.h"
#include <cmath>
#include <memory>
#include <vector>

#include "../lib/abecontextzzg.h"

#include <iostream>
#include <fstream>

using namespace lbcrypto;
int main() {

long int x=444;
long int n=10007;
std::cout << "il reciproco di " << x << " mod " << n << " è " << reciproco(x,n) << std::endl;
/*


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
//Matrix<NativePoly> matrice(1,9);

std::vector<usint> attributi(6);
std::vector<int> access_policy(6);

//matrice.SetSize(1,9);
//std::cout << mpk.GetA().GetAllocator();
std::fstream my_file66;
my_file66.open("../src/files/A2.txt", std::ios::out);
//mpk.GetA().save(my_file66,1);

NativePoly pippo=contesto.GenerateRandomElement();
//matrice.HStack(pippo);
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
*/
return 0;
}
