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

		/*
        void Setup(usint dd,CPABEMasterPublicKeyZZG<NativePoly>* pk,
                   CPABEMasterSecretKeyZZG<NativePoly>* sk)
        {
            
          
    
        }
		*/
		void Setup(shared_ptr<ABECoreParams<Element>> bm_params,
				        usint dd,
				        CPABEMasterPublicKeyZZG<NativePoly>* mpkZZG,
                   		CPABEMasterSecretKeyZZG<NativePoly>* mskZZG,
				        CPABEMasterPublicKey<NativePoly>* mpk,
                   		CPABEMasterSecretKey<NativePoly>* msk) {
		  auto m_params = std::static_pointer_cast<CPABEParams<Element>>(bm_params);
		  //auto* mpk = static_cast<CPABEMasterPublicKey<Element>*>(bmpk);
		  //auto* msk = static_cast<CPABEMasterSecretKey<Element>*>(bmsk);

		  typename Element::DugType& dug = m_params->GetDUG();
		  usint m_N = m_params->GetTrapdoorParams()->GetN();
		  usint m_ell = m_params->GetEll();
		  usint m_m = m_params->GetTrapdoorParams()->GetK() + 2;
		  auto zero_alloc = Element::Allocator(
			  m_params->GetTrapdoorParams()->GetElemParams(), Format::COEFFICIENT);

		  Matrix<Element> pubElemAi(zero_alloc, m_ell + dd, m_m);
		  Element pubElemU(pubElemAi(0, 0));

		  if (pubElemU.GetFormat() != Format::COEFFICIENT) pubElemU.SwitchFormat();
		  // always sample in Format::COEFFICIENT format
		  pubElemU.SetValues(dug.GenerateVector(m_N), Format::COEFFICIENT);
		  pubElemU.SwitchFormat();  // always kept in Format::EVALUATION format

		  for (usint i = 0; i < pubElemAi.GetRows(); i++){
			for (usint j = 0; j < pubElemAi.GetCols(); j++) {
			  if ((pubElemAi)(i, j).GetFormat() != Format::COEFFICIENT)
				(pubElemAi)(i, j).SwitchFormat();
			  // always sample in Format::COEFFICIENT format
			  (pubElemAi)(i, j).SetValues(dug.GenerateVector(m_N),
				                            Format::COEFFICIENT);
			  // always kept in Format::EVALUATION format
			  (pubElemAi)(i, j).SwitchFormat();
			}
		  }


		  mpkZZG->Ai=pubElemAi;
		  mpkZZG->u=pubElemU;
		  /*std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> keypair =
			  RLWETrapdoorUtility<Element>::TrapdoorGen(
				  m_params->GetTrapdoorParams()->GetElemParams(), SIGMA,
				  m_params->GetTrapdoorParams()->GetBase(), false);
		  mpkZZG->A=keypair.first;
		  mskZZG->TA=keypair.second;
		  */
		  contextZZ.Setup(mpk, msk);
		}

};
}
#endif

