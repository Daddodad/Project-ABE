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

        void Setd(usint jj) {d=jj;}

        int Getj() {return j;}
		
        void GenerateCPABEContextZZG(usint nelementi,usint ringsize,usint base) {
            contextZZ.GenerateCPABEContext(nelementi, ringsize, base);
        };

		void Setup(shared_ptr<ABECoreParams<Element>> bm_params,
				        CPABEMasterPublicKeyZZG<NativePoly>* mpkZZG,
                   		CPABEMasterSecretKeyZZG<NativePoly>* mskZZG) {
    
         auto m_params = std::static_pointer_cast<CPABEParams<Element>>(bm_params);

	     typename Element::DugType& dug = m_params->GetDUG();
		 usint m_N = m_params->GetTrapdoorParams()->GetN(); //MconN 
         usint m_ell = m_params->GetEll();
		 usint m_m = m_params->GetTrapdoorParams()->GetK() + 2;
		 auto zero_alloc = Element::Allocator(
			  m_params->GetTrapdoorParams()->GetElemParams(), Format::COEFFICIENT);

		 Matrix<Element> pubElemAi(zero_alloc, m_ell + d, m_m);
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

        void KeyGenZZG(shared_ptr<ABECoreParams<Element>> bm_params,
				        CPABEMasterPublicKeyZZG<NativePoly> mpkZZG,
                   		CPABEMasterSecretKeyZZG<NativePoly> mskZZG,
                        const CPABEUserAccess<Element>& id,
                        CPABESecretKey<Element>* usk) {

        auto m_params = std::static_pointer_cast<CPABEParams<Element>>(bm_params);
        usint m_ell = m_params->GetEll();
        usint m_k = m_params->GetTrapdoorParams()->GetK();
        usint m_m = m_k + 2;
        usint m_N = m_params->GetTrapdoorParams()->GetN();
        usint m_base = m_params->GetTrapdoorParams()->GetBase();
        double sb = SPECTRAL_BOUND(m_N, m_k, m_base);
        auto ep = m_params->GetTrapdoorParams()->GetElemParams();

        usint poly[m_N][(d+1)];
        long int q= mpkZZG.u.GetModulus().ConvertToInt();
        //std::cout << q << "\n";
        srand(time(0));
        poly[0][0]=rand() % q;
        std::cout << poly[0][0] << "\n";
        usint ii=2;
        poly[ii][ii]=3;
        for (usint i = 0; i < m_N; i++){
            for (usint j=1; j<d+1;  j++)
                poly[i][j]=rand() % q;
            }
        }

/*
        // always sample in Format::COEFFICIENT format
        Matrix<Element> skB(Element::MakeDiscreteGaussianCoefficientAllocator(
                          ep, Format::COEFFICIENT, sb),
                      m_m, m_ell); //le colonne sono i vettori e_i

        // #pragma omp parallel for
        for (usint j = 0; j < m_ell; j++) {
            for (usint i = 0; i < m_m; i++) skB(i, j).SwitchFormat(); //cambia in EVAL
        }

        Element y(ep, Format::EVALUATION, true);
        Element z(ep, Format::EVALUATION, true);
        std::vector<Element> z_vectors(m_ell);

        const Matrix<Element>& pubElemBPos = mpk.GetBPos();
        const Matrix<Element>& pubElemBNeg = mpk.GetBNeg();
        const std::vector<usint> s = id.GetS(); //letteralmente l'user attribute list
        const Element& pubElemD = mpk.GetPubElemD();

        // #pragma omp parallel for firstprivate(z) num_threads(4)
        for (usint i = 0; i < m_ell; i++) {
            if (s[i] == 1) {
             z = pubElemBPos(i, 0) * skB(0, i);
             for (usint j = 1; j < m_m; j++) z += pubElemBPos(i, j) * skB(j, i);
         } else {
             z = pubElemBNeg(i, 0) * skB(0, i);
            for (usint j = 1; j < m_m; j++) z += pubElemBNeg(i, j) * skB(j, i);
         }
                 z_vectors.at(i) = z;
          }

          for (usint i = 0; i < m_ell; i++) {
            y += z_vectors.at(i);
          }

          y = pubElemD - y;

          Matrix<Element> skA(
              Element::Allocator(m_params->GetTrapdoorParams()->GetElemParams(),
                                 Format::EVALUATION),
              m_m, 1);
          skA = RLWETrapdoorUtility<Element>::GaussSamp(
              m_N, m_k, mpk.GetA(), msk.GetTA(), y,
              m_params->GetTrapdoorParams()->GetDGG(),
              m_params->GetTrapdoorParams()->GetDGGLargeSigma(), m_base);
          Matrix<Element> sk(Element::Allocator(ep, Format::COEFFICIENT), m_m,
                             m_ell + 1);
          for (usint i = 0; i < m_m; i++) (sk)(i, 0) = skA(i, 0);

          // #pragma omp parallel for num_threads(4)
          for (usint i = 0; i < m_ell; i++)
            for (usint j = 0; j < m_m; j++) (sk)(j, i + 1) = skB(j, i);

          usk->SetSK(std::make_shared<Matrix<Element>>(sk));
*/
  };

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

