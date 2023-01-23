#ifndef ABE_ABECONTEXTZZG_H
#define ABE_ABECONTEXTZZG_H

#include <memory>
#include <vector>

#include "abeparamset.h"
#include "cpabe.h"
#include "ibe.h"
#include "abecontext.h"
#include "abecore.h"
#include "palisade.h"
#include "encoding/plaintextfactory.h"
#include "lattice/elemparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/ilparams.h"
#include "lattice/trapdoorparameters.h"
#include "math/backend.h"
#include "math/distrgen.h"
#include "utils/inttypes.h"
namespace lbcrypto {

template <class Element>
class CPABEMasterPublicKeyZZG{
 public:
    
    Matrix<Element> B;
    Matrix<Element> A;
    Matrix<Element> Ai;
    Element u;
    
  //f@brief Default destructor
  ~CPABEMasterPublicKeyZZG() {}
   //@brief Default constructor
  CPABEMasterPublicKeyZZG() {}

    CPABEMasterPublicKeyZZG(Matrix<Element> BB, Matrix<Element> AA, Matrix<Element> Aii, Element uu){
    B=BB;
    A=AA;
    Ai=Aii;
    u=uu;
  }
    
};

template <class Element>
class CPABEMasterSecretKeyZZG{
 public:
    CPABEMasterPublicKeyZZG<Element> msk;
    RLWETrapdoorPair<Element> TA;
    
  //f@brief Default destructor
  ~CPABEMasterSecretKeyZZG() {}
  //@brief Default constructor
  CPABEMasterSecretKeyZZG() {}
  /*
   *@brief Constructor for master public key
   *@param A Matrix of element generated during trapdoor generation
   *@param Bpos Matrix of positive attributes
   *@param Bneg Matrix of negative attributes
   *@param pubElemD the public element
   */
  CPABEMasterSecretKeyZZG(CPABEMasterPublicKeyZZG<Element> MSK, RLWETrapdoorPair<Element> TAA){
    msk=MSK;
    TA=TAA;
  }
};


template <class Element>
class ABEContextZZG {
    public:
        int j;
        ABEContext<Element> contextZZ;
        usint d;
    
        //Distruttore di Default
        ~ABEContextZZG() {}
        //Costruttore di Default
        ABEContextZZG() {
        }

        int StampaCiao(int i){
        std::cout << "ciao\n";
        i++;
        return i+1;};
    
        void Setj(int jj) {j=jj;}
        
        int Getj() {return j;}

        void GenerateCPABEContextZZG(usint nelementi,usint ringsize,usint base) {
            contextZZ.GenerateCPABEContext(nelementi, ringsize, base);
        };

        void Setup(usint dd,CPABEMasterPublicKeyZZG<NativePoly>* pk,
                   CPABEMasterSecretKeyZZG<NativePoly>* sk)
        {
            
            
    
        }

};
}
#endif

