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

    Matrix<Element> GetB(){return B;};
    Matrix<Element> GetA(){return A;};
    Matrix<Element> GetAi(){return Ai;};
    Element GetU(){return u;};
    
};

template <class Element>
class CPABEMasterSecretKeyZZG{
 public:
    CPABEMasterPublicKeyZZG<Element> mpk;
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
  CPABEMasterSecretKeyZZG(CPABEMasterPublicKeyZZG<Element> MPK, RLWETrapdoorPair<Element> TAA){
    mpk=MPK;
    TA=TAA;
  }
    
    CPABEMasterPublicKeyZZG<Element> GetMpk(){return mpk;};
    RLWETrapdoorPair<Element> GetTA(){return TA;};
};


template <class Element>
class ABEContextZZG {
    public:
        int j;
        ABEContext<Element> contextZZ;
        usint d;

        usint temprs;
        usint tempell;  
        usint tempbase;
    
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
            temprs=ringsize;
            tempbase=base;
            tempell=nelementi;
        };

		void Setup(shared_ptr<ABECoreParams<Element>> bm_params,
				        usint dd,
				        CPABEMasterPublicKeyZZG<NativePoly>* mpkZZG,
                   		CPABEMasterSecretKeyZZG<NativePoly>* mskZZG) {
    
         auto m_params = std::static_pointer_cast<CPABEParams<Element>>(bm_params);

	     typename Element::DugType& dug = m_params->GetDUG();
		 usint m_N = m_params->GetTrapdoorParams()->GetN(); //MconN 
         usint m_ell = m_params->GetEll();
		 usint m_m = m_params->GetTrapdoorParams()->GetK() + 2;
		 auto zero_alloc = Element::Allocator(
			  m_params->GetTrapdoorParams()->GetElemParams(), Format::COEFFICIENT);

		 Matrix<Element> pubElemAi(zero_alloc, m_ell + dd, m_m);
         Matrix<Element> pubElemB(zero_alloc,1,m_m);
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

          for (usint i = 0; i < pubElemB.GetRows(); i++){
	        for (usint j = 0; j < pubElemB.GetCols(); j++) {
			    if ((pubElemB)(i, j).GetFormat() != Format::COEFFICIENT)
				    (pubElemB)(i, j).SwitchFormat();
			     // always sample in Format::COEFFICIENT format
			    (pubElemB)(i, j).SetValues(dug.GenerateVector(m_N),
				                            Format::COEFFICIENT);
			    // always kept in Format::EVALUATION format
			     (pubElemB)(i, j).SwitchFormat();
			    }
		  }

		  std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> keypair =
			  RLWETrapdoorUtility<Element>::TrapdoorGen(
				  m_params->GetTrapdoorParams()->GetElemParams(), SIGMA,
				  m_params->GetTrapdoorParams()->GetBase(), false);

		  mpkZZG->A=keypair.first;
          mpkZZG->Ai=pubElemAi;
		  mpkZZG->u=pubElemU;
          mpkZZG->B=pubElemB;

		  mskZZG->TA=keypair.second;
          mskZZG->mpk.Ai=pubElemAi;
          mskZZG->mpk.u=pubElemU;
          mskZZG->mpk.A=keypair.first;
          mskZZG->mpk.B=pubElemB;
		}

        void ParamsGenCPABEZZG(
        usint ringsize, usint ell, usint base,
        shared_ptr<ABECoreParams<Element>>& m_params) {
        // smoothing parameter - also standard deviation for noise Elementnomials
        double sigma = SIGMA;

        // Correctness constraint
        auto qCorrectness = [&](uint32_t n, uint32_t m) -> double {
        return 256 * sigma * SPECTRAL_BOUND(n, m - 2, base) *
           sqrt(m * n * (ell + 1));
        };

        double qPrev = 1e6;
        double q = 0;
        usint k = 0;
        usint m = 0;

        // initial value
        k = floor(log2(qPrev - 1.0) + 1.0);
        m = ceil(k / log2(base)) + 2;
        q = qCorrectness(ringsize, m);

        // get a more accurate value of q
         while (std::abs(q - qPrev) > 0.001 * q) {
            qPrev = q;
            k = floor(log2(qPrev - 1.0) + 1.0);
            m = ceil(k / log2(base)) + 2;
            q = qCorrectness(ringsize, m);
        }
        usint sm = ringsize * 2;
        typename Element::DggType dgg(sigma);
        typename Element::DugType dug;
        typename Element::Integer smodulus;
        typename Element::Integer srootOfUnity;

        smodulus = FirstPrime<typename Element::Integer>(floor(log2(q - 1.0)) + 1.0,
                                                   2 * ringsize);
        srootOfUnity = RootOfUnity(sm, smodulus);
        dug.SetModulus(smodulus);
        ILParamsImpl<typename Element::Integer> ilParams(sm, smodulus, srootOfUnity);

        ChineseRemainderTransformFTT<typename Element::Vector>::PreCompute(
            srootOfUnity, sm, smodulus);
        DiscreteFourierTransform::PreComputeTable(sm);
        EncodingParams eparams(std::make_shared<EncodingParamsImpl>(2));
        auto silparams =
            std::make_shared<ILParamsImpl<typename Element::Integer>>(ilParams);
        RLWETrapdoorParams<Element> tparams(silparams, dgg, sigma, base);
        m_params = std::make_shared<CPABEParams<Element>>(
            std::make_shared<RLWETrapdoorParams<Element>>(tparams), ell, dug,
            eparams);
}

};


} //end libcrypto
#endif

