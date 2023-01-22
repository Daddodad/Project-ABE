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

    size_t rows=5;
    size_t cols=5;
    Matrix<int64_t> test([]() { return 0; }, rows, cols);
    std::cout << test.SerializedObjectName();
    //auto zero_alloc = NativePoly::Allocator(5, Format::EVALUATION);
    //test.Matrix();

    //test.SetSize(rows,cols);
    
    
    std::fstream my_file;
    my_file.open("../src/files/mtest.txt", std::ios::out);
    if (!my_file) {
		std::cout << "File not opened!\n";
	}
	else {
		std::cout << "File opened successfully!\n";
        my_file << test.ExtractRow(rows-1);
		my_file.close(); 
	}

return 0;
}
