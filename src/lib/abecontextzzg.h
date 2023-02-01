#ifndef ABE_ABECONTEXTZZG_H
#define ABE_ABECONTEXTZZG_H

#include <memory>
#include <vector>
#include <random>

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
#define FLT_MAX 3.402823466e+38F 

namespace lbcrypto {

template <class Element>
class CPABEMasterPublicKeyZZG{
 public:
    
  Matrix<Element> B;
  Matrix<Element> Ai;
  Element u;
    
  //f@brief Default destructor
  ~CPABEMasterPublicKeyZZG() {}
   //@brief Default constructor
  CPABEMasterPublicKeyZZG() {}
  /*
  CPABEMasterPublicKeyZZG(Matrix<Element> BB, Matrix<Element> AA, Matrix<Element> Aii, Element uu){
    B=BB;
    A=AA;
    Ai=Aii;
    u=uu;
  }
  */

    Matrix<Element> GetB(){return B;};
    const Matrix<Element>& GetA() const { return *m_A; }
    Matrix<Element> GetAi(){return Ai;};
    Element GetU(){return u;};
    
    void SetA(shared_ptr<Matrix<Element>> A) { this->m_A = A; }
    
  private:
  	shared_ptr<Matrix<Element>> m_A;  
    
};

template <class Element>
class CPABEMasterSecretKeyZZG{
 public:
    CPABEMasterPublicKeyZZG<Element> mpk;
    
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
  /* 
  CPABEMasterSecretKeyZZG(CPABEMasterPublicKeyZZG<Element> MPK, RLWETrapdoorPair<Element> TAA){
    mpk=MPK;
    TA=TAA;
  }
  */  
    CPABEMasterPublicKeyZZG<Element> GetMpk(){return mpk;};
    const RLWETrapdoorPair<Element>& GetTA() const { return *m_TA; }
    void SetTA(shared_ptr<RLWETrapdoorPair<Element>> TA) { this->m_TA = TA; }
    
  private:
  	shared_ptr<RLWETrapdoorPair<Element>> m_TA; 
};

template <class Element>
class CPABECiphertextZZG{
 public:
  /*
   *@brief Default destructor
   */
  ~CPABECiphertextZZG() = default;
  /*
   *@brief Default constructor
   */
  CPABECiphertextZZG() = default;
  /*
   *@brief Accessor function for the helper cNeg for ciphertext
   *@return Helper cNeg for ciphertext
   */
  const Matrix<Element>& GetC_primo() const { return *m_c_primo; }
  /*
   *@brief Mutator function for the helper cNeg for ciphertext
   *@param cNeg Helper for ciphertext
   */
  void SetC_primo(shared_ptr<Matrix<Element>> c_primo) { this->m_c_primo = c_primo; }
  /*
   *@brief Accessor function for the helper CW for ciphertext
   *@return Helper CW for ciphertext
   */
  const Matrix<Element>& GetC_i() const { return *m_c_i; }
  /*
   *@brief Mutator function for the helper CW for ciphertext
   *@param CW Helper for ciphertext
   */
  void SetC_i(shared_ptr<Matrix<Element>> c_i) { this->m_c_i = c_i; }
  
  const Element& GetC0() const { return m_c0; }
  /*
   *@brief Mutator function for the ciphertext
   *@param c1 Ciphertext
   */
  void SetC0(const Element& c0) { this->m_c0 = c0; }

 private:
  Element m_c0;

  // Vectors used to help decryption process
  shared_ptr<Matrix<Element>> m_c_primo, m_c_i;
  /**
   *@brief Overloaded dummy method
   */
  void forceImplement() {}
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
				        CPABEMasterPublicKeyZZG<Element>* mpkZZG,
                   		CPABEMasterSecretKeyZZG<Element>* mskZZG) {
    
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
		 
		  mpkZZG->SetA(std::make_shared<Matrix<Element>>(keypair.first));
          mpkZZG->Ai=pubElemAi;
		  mpkZZG->u=pubElemU;
          mpkZZG->B=pubElemB;

		  mskZZG->SetTA(std::make_shared<RLWETrapdoorPair<Element>>(keypair.second));
          mskZZG->mpk.Ai=pubElemAi;
          mskZZG->mpk.u=pubElemU;
          mskZZG->mpk.SetA(std::make_shared<Matrix<Element>>(keypair.first));
          mskZZG->mpk.B=pubElemB;
          
		}

       void KeyGenZZG(shared_ptr<ABECoreParams<Element>> bm_params,
				        CPABEMasterPublicKeyZZG<Element> mpkZZG,
                   		CPABEMasterSecretKeyZZG<Element> mskZZG,
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
		auto zero_alloc = Element::Allocator(ep, Format::EVALUATION);
		auto uniform_alloc = Element::MakeDiscreteUniformAllocator(ep, Format::EVALUATION);
		Matrix<Element> p(zero_alloc, 1, d+1, uniform_alloc);
		//size_t i=0, j=4;
		//std::cout << p(i,j)<< std::endl; // p(0,j)[k] è l'elemento j-esimo del k-esimo polinomio
		//std::cout << p.GetRows() << std::endl;
		//std::cout << p.GetCols() << std::endl;
		p(0,0) = mpkZZG.u;
		
		Matrix<Element> result(zero_alloc, 1, mpkZZG.Ai.GetCols());
		
		
		int s_size = 0;
		for (usint j=0; j<id.GetS().size() ; j++){
			if (id.GetS()[j]==1){
				s_size++;
			}
		}                    
            
        // Algoritmo SampleLeft, facente utilizzo di SamplePre da palisade
            
        Matrix<Element> e1(Element::Allocator(m_params->GetTrapdoorParams()->GetElemParams(),
                                 Format::EVALUATION), m_m, 1);
                                 
        auto gaussian_alloc = Element::MakeDiscreteGaussianCoefficientAllocator(ep, Format::EVALUATION, sb);
        // Format qui e nello uniform allocator determina il Formato restituito (La generazione viene invece sempre
        // fatta in COEFFICIENT) 
        
        Matrix<Element> e(Element::Allocator(ep, Format::EVALUATION), 2*m_m,
                             s_size + d);                         
        //std::vector<Matrix<Element>> e(s_size + d);  
      
        //std::cout << m_ell+d << std::endl;
       

        Matrix<Element> u_tilde(Element::Allocator(m_params->GetTrapdoorParams()->GetElemParams(),
                                 Format::EVALUATION), 1, s_size + d);
                                 
//float L;
//Element cont(m_params->GetTrapdoorParams()->GetElemParams(),
//               Format::EVALUATION, true);                                             

//Matrix<Element> u_tilde2(Element::Allocator(m_params->GetTrapdoorParams()->GetElemParams(),
//                                 Format::EVALUATION), 1, s_size + d);  


//Matrix<Element> Acopy(Element::Allocator(m_params->GetTrapdoorParams()->GetElemParams(),
//                                 Format::EVALUATION), 1, m_m);                            
  
//std::cout << mpkZZG.GetA().GetRows() << std::endl;
//std::cout << mpkZZG.GetA().GetCols() << std::endl;
//std::cout << m_m << std::endl;
        
        Element temp;
        
        /*
        for (usint i=0; i<m_ell +d ; i++){
        	temp = p(0,0);
        	for (usint h=1; h< d+1; h++){
        		 temp += p(0,h)*pow(i,h);
        	}
        	u_tilde(0,i) = temp;
        }   
       	*/ 
       	                               
        usint h=0;
        std::cout << id.GetS() << std::endl;
        for (usint j=0; j<m_ell+d; j++){    
        	if(id.GetS()[j]==1 || m_ell<=j){   
		    	usint i = 0;
				for (auto& elem : mpkZZG.Ai.GetData()[j]) {
				  result(0, i) = elem;
				  i++;
				}   
				temp = p(0,0);
				for (usint k=1; k< d+1; k++){
        		 temp += p(0,k)*pow(j+1,k);
        		}
        		u_tilde(0,h) = temp;
//std::cout << temp << std::endl;        		
//u_tilde2(0,h) = temp;
//std::cout << h << j << std::endl;  
//std::cout << result(0,0)[0] << std::endl;      		
				Matrix<Element> e2(zero_alloc, m_m, 1, gaussian_alloc); 
				e1 = RLWETrapdoorUtility<Element>::GaussSamp(
				      m_N, m_k, mpkZZG.GetA(), mskZZG.GetTA(), u_tilde(0,h).Minus(result.Add(mpkZZG.B).Mult(e2)(0,0)),
				      m_params->GetTrapdoorParams()->GetDGG(),
				      m_params->GetTrapdoorParams()->GetDGGLargeSigma(), m_base);           
				for (usint l = 0; l < m_m; l++){
            		(e)(l, h) = e1(l, 0);
            		(e)(l + m_m, h) = e2(l, 0);
				}
				//e(h) = e1;
				//e[h].VStack(e2);
//Acopy = mpkZZG.GetA();				        
//cont = (Acopy.HStack(result.Add(mpkZZG.B))*e.ExtractCol(h))(0,0);
//std::cout << cont - u_tilde2(0,h) << std::endl;				 
				h++;
//std::cout << mpkZZG.B(0,0)[0] << std::endl;  				
//std::cout << result(0,0)[0] << std::endl;  				
		    }                          
        } 
        
        usk->SetSK(std::make_shared<Matrix<Element>>(e));
        //std::cout << usk->GetSK().GetRows() << std::endl;  
        //std::cout << usk->GetSK().GetCols() << std::endl; 
        //std::cout << usk->GetSK() << std::endl;   
        
  };
 
  void EncryptZZG(shared_ptr<ABECoreParams<Element>> bm_params,
                                   CPABEMasterPublicKeyZZG<Element> mpkZZG,
                        		   const CPABEAccessPolicy<Element> ap,
                        		   usint t,
                                   Plaintext pt,
                                   CPABECiphertextZZG<Element>* ctext) {
  auto m_params = std::static_pointer_cast<CPABEParams<Element>>(bm_params);
  Element ptxt = pt->GetElement<Element>();
  //const auto& mpk = static_cast<const CPABEMasterPublicKey<Element>&>(bmpk);
  //const auto& ap = static_cast<const CPABEAccessPolicy<Element>&>(bap);
  //auto* ctext = static_cast<CPABECiphertext<Element>*>(bctext);
  usint lenW = 0;
  usint m_ell = m_params->GetEll();
  usint m_N = m_params->GetTrapdoorParams()->GetN();
  usint m_m = m_params->GetTrapdoorParams()->GetK() + 2;
  const std::vector<int32_t>& w = ap.GetW();
  auto ep = m_params->GetTrapdoorParams()->GetElemParams();
  Element D(m_params->GetTrapdoorParams()->GetElemParams(),
               Format::EVALUATION, true);            
  D = 1;
  for (usint i=2; i<=m_ell+d; i++){
  	D = D*i;
  }
  
  std::cout << "D: " << D[0] << std::endl;   
             
  D = D*D;
  std::cout << std::fixed;
  std::cout << "t_gamma: " << tgamma(m_ell + d + 1) << std::endl;  
  
  for (usint i = 0; i < m_ell; i++)
    if (w[i] != 0) lenW++;

  std::cout << "LenW" << lenW << std::endl;	

  typename Element::DugType& dug = m_params->GetDUG();

  Element s(dug, m_params->GetTrapdoorParams()->GetElemParams(),
            Format::COEFFICIENT);
  s.SwitchFormat();  
    
  // compute c0
  Element qHalf(m_params->GetTrapdoorParams()->GetElemParams(),
                Format::COEFFICIENT, true);
  typename Element::Integer m_q =
      m_params->GetTrapdoorParams()->GetElemParams()->GetModulus();
  qHalf += (m_q >> 1);
  qHalf.SwitchFormat();
  qHalf.AddILElementOne();
  
  //std::cout << qHalf << std::endl;

  Element err0(m_params->GetTrapdoorParams()->GetElemParams(),
               Format::COEFFICIENT, true);  // error term
  err0.SetValues(
      m_params->GetTrapdoorParams()->GetDGG().GenerateVector(m_N, m_q),
      Format::COEFFICIENT);
  err0.SwitchFormat();
  if (ptxt.GetFormat() != Format::EVALUATION) ptxt.SwitchFormat();
  if (mpkZZG.u.GetFormat() != Format::EVALUATION) {
    mpkZZG.u.SwitchFormat();
  }
  
  Element ctC0(m_params->GetDUG(),
               m_params->GetTrapdoorParams()->GetElemParams(),
               Format::EVALUATION);   
  //std::cout << s << std::endl;
  //std::cout << mpkZZG.u << std::endl;
  //std::cout << s*mpkZZG.u << std::endl;
  //std::cout << "Plaintext*q_half:  " <<ptxt*qHalf << std::endl;  
  //std::cout << "s[0]: " << s[0] << std::endl;                 
  //std::cout << "u[0]: " << mpkZZG.u[0] << std::endl;  
  std::cout << "D: " << D[0] << std::endl;  
  //std::cout << "err0[0]: " << err0[0] << std::endl;             
  //std::cout << "s*u[0]: " << (s * mpkZZG.u)[0] << std::endl;  
  //std::cout << "D*err0[0]: " << (D*err0)[0] << std::endl;   
                         
  ctC0 = s * mpkZZG.u + D[0]*err0 + ptxt * qHalf;
  
  //std::cout << "ctC0[0]: " << ctC0[0] << std::endl; 
  
  //std::cout << ctC0 << std::endl; 
  
  Matrix<Element> err_primo(Element::MakeDiscreteGaussianCoefficientAllocator(
                          m_params->GetTrapdoorParams()->GetElemParams(),
                          Format::COEFFICIENT, SIGMA), 1,
                      m_m);	
  
  for (usint i = 0; i < m_m; i++) {
    err_primo(0, i).SwitchFormat();
  }
  
  const Matrix<Element>& pubA = mpkZZG.GetA();
                      
  Matrix<Element> ctCprimo(Element::Allocator(ep, Format::EVALUATION), 1,
                      m_m);                 
                      
 for (usint j = 0; j < m_m; j++)
    ctCprimo(0, j) = pubA(0, j) * s + D*err_primo(0, j);   
 
 //std::cout << ctCprimo << std::endl;
 
 Matrix<Element> ctCi(Element::Allocator(ep, Format::EVALUATION), lenW + d - t + 1,
                      m_m);

 Matrix<Element> AiCopy(Element::Allocator(ep, Format::EVALUATION), 1, mpkZZG.Ai.GetCols());          
 
 //auto uniform_alloc = Element::MakeDiscreteUniformAllocator(ep, Format::EVALUATION);
 std::random_device rd;
 std::mt19937 gen(rd());
 std::uniform_int_distribution<int> distribution(0, 1);         
 //std::cout << distribution(gen) << std::endl;
 //std::cout << err0 << std::endl;
 //std::cout << (-1)*err0 << std::endl;
 /*
 Matrix<usint> R; 
 int many1 = 0;
 int manymeno1 = 0;
 uint64_t tmp;
 
 for (usint j = 0; j < m_m; j++){
 	for (usint k=0; k<m_m; k++){
 		tmp = distribution(gen);
 		std::cout << "tmp" << tmp << std::endl;
		if(tmp==1){
			R(j,k) = 1;
			std::cout << "R" << R(j,k) << std::endl;
			many1++;
		} else {
			R(j,k) = m_q.ConvertToInt() -1;
			std::cout << "R" << R(j,k) << std::endl;
			manymeno1++;
		}
	}	
 }
 
 std::cout << R << std::endl;
 */
 //std::cout << R << std::endl;
 //std::cout << many1 << std::endl;
 //std::cout << manymeno1 << std::endl;
 usint k=0;
 int r;  
 Element somma(m_params->GetTrapdoorParams()->GetElemParams(),
               Format::EVALUATION, true);                  
 for (usint i = 0; i < m_ell + d - t + 1; i++) {
 	if(ap.GetW()[i]==1 || m_ell<=i){   
		usint h = 0;
		for (auto& elem : mpkZZG.Ai.GetData()[i]) {
			AiCopy(0, h) = elem;
			h++;
		}
	 	for (usint j = 0; j < m_m; j++){
	 		somma = 0;
			for (usint l=0; l< m_m; l++){
				r = distribution(gen);
				if(r!=1){
					r = -1;
				}
				//std::cout << r << std::endl;
				somma += r*err_primo(0,l);
			}
			ctCi(k, j) = AiCopy.Add(mpkZZG.B)(0,j) * s + D*somma;  //D*R(0, j)*err_primo(0, j);
		}
		k++;
	}		
 }                    

 //std::cout << c_primo.GetRows() << std::endl;
 //std::cout << c_primo.GetCols() << std::endl;   
 
  ctext->SetC0(ctC0);
  ctext->SetC_primo(std::make_shared<Matrix<Element>>(ctCprimo));
  ctext->SetC_i(std::make_shared<Matrix<Element>>(ctCi));
  
  //std::cout << ctext->GetC0() << std::endl;
  
}


Plaintext DecryptZZG(shared_ptr<ABECoreParams<Element>> bm_params,
                                   const CPABEAccessPolicy<Element> ap,
                                   const CPABEUserAccess<Element> ua,
                                   usint t,
                                   CPABESecretKey<Element> usk,
                                   CPABECiphertextZZG<Element> ctext) {
                                                                
  auto m_params = std::static_pointer_cast<CPABEParams<Element>>(bm_params);
  //const auto& usk = static_cast<const CPABESecretKey<Element>&>(busk);
  //const auto& ap = static_cast<const CPABEAccessPolicy<Element>&>(bap);
  //const auto& ua = static_cast<const CPABEUserAccess<Element>&>(bua);
  //const auto& ctext = static_cast<const CPABECiphertext<Element>&>(bctext);
  usint m_ell = m_params->GetEll();
  usint m_N = m_params->GetTrapdoorParams()->GetN();
  
  const std::vector<int32_t> w = ap.GetW();
  const std::vector<usint> s = ua.GetS();
  
  usint cont=0;
  
  for (usint j=0; j<m_ell; j++){
  	if (w[j]==1 && s[j]==1){
  		cont++;
  	}
  }
  
  if (cont<t){
  	std::cerr << "Errore: il numero minimo di attributi non è raggiunto" << std::endl;
  	abort();
  }
  
  Plaintext ptext = PlaintextFactory::MakePlaintext(CoefPacked, m_params->GetTrapdoorParams()->GetElemParams(),
      m_params->GetEncodingParams());
  Element* dtext = &(ptext->GetElement<Element>());      

  dtext->SetValuesToZero();
  
  if (dtext->GetFormat() != Format::EVALUATION) dtext->SwitchFormat();

  const Matrix<Element> sk = usk.GetSK();
  const Matrix<Element> ctCprimo = ctext.GetC_primo();
  const Matrix<Element> ctCi = ctext.GetC_i();
  const Element ctC0 = ctext.GetC0();

  typename Element::Integer m_q =
      m_params->GetTrapdoorParams()->GetElemParams()->GetModulus();
  usint m_m = m_params->GetTrapdoorParams()->GetK() + 2;
  
  std::vector<usint> s_primo, w_primo;
  
  for (usint i=0; i<m_ell+d; i++){
  	if (s[i]==1 || m_ell<=i){
  		s_primo.push_back(i);
  	} 
  }
  std::cout << s_primo << std::endl;
  
  for (usint i=0; i<m_ell + d -t +1; i++){
  	if (w[i]==1 || m_ell<=i){
  		w_primo.push_back(i);
  	} 
  }
  std::cout << w_primo << std::endl;
  
  std::vector<usint> s_w_primo, J;
  
  std::set_intersection(s_primo.begin(), s_primo.end(), w_primo.begin(), w_primo.end(), 		std::back_inserter(s_w_primo));
  
  std::cout << s_w_primo << std::endl;
  
  std::random_device rd;
  std::mt19937 gen(rd());
  
  int r;
  
  for (usint i=0; i<=d; i++){
  	std::uniform_int_distribution<int> distribution(0, s_w_primo.size()-1);
  	r = distribution(gen);
  	J.push_back(s_w_primo[r]);
  	s_w_primo.erase(s_w_primo.begin() + r);
  	//std::cout << r << " " << s_w_primo << std::endl;
  } 
  
  std::sort(J.begin(), J.end());
  
  std::cout << J << std::endl;
  
  auto zero_alloc = Element::Allocator(
			  m_params->GetTrapdoorParams()->GetElemParams(), Format::EVALUATION);
  Matrix<Element> b_j(zero_alloc, 1, d+1);
  //std::cout << b_j << std::endl;
  
  Matrix<Element> test(zero_alloc, 1, 2*m_m);
 	
  usint s_primo_pos, w_primo_pos, index_j;
  	
  for (usint j=0; j<=d; j++){
  	index_j = J[j];
  	s_primo_pos=0;
  	w_primo_pos=0;
  	for (usint k=0; k<s_primo.size(); k++){
  		if (s_primo[k]==index_j){
  			s_primo_pos = k;
  		}
  	}
  	for (usint k=0; k<w_primo.size(); k++){
  		if (w_primo[k]==index_j){
  			w_primo_pos = k;
  		}
  	}
  	//std::cout << "index_j" << index_j << std::endl;
  	//std::cout << "s_pos" << s_primo_pos << std::endl;
  	//std::cout << "w_pos" << w_primo_pos << std::endl;
  	for (usint i=0; i<m_m; i++){
		test(0,i) = ctext.GetC_primo()(0,i);
		test(0,m_m + i) = ctext.GetC_i().ExtractRow(w_primo_pos)(0,i);
	}
  	for (usint i=0; i<2*m_m; i++){
  		b_j(0,j) += usk.GetSK()(i,s_primo_pos)*test(0,i);	
  	}		
  }	
  
  //std::cout << b_j << std::endl;
  //std::cout << b_j.GetRows() << std::endl;
  //std::cout << b_j.GetCols() << std::endl;
  
  //float L;              
  
  float index_i;
  
long int modulus=m_q.ConvertToInt();
std::cout << modulus << std::endl;
std::vector<long int> L(d+1);
long int tempij;

typename Element::DugType& dug = m_params->GetDUG();

Element temptemp(dug, m_params->GetTrapdoorParams()->GetElemParams(),
            Format::COEFFICIENT);
temptemp.SwitchFormat();
Element inversotemp=temptemp.MultiplicativeInverse();  //cont è un NATIVEPOLY di 0

for (usint j=0; j<=d; j++){
  	index_j = J[j]+1;
  	L[j]=1;
    tempij=1;
  	for (usint i=0; i<=d; i++){
  		index_i = J[i]+1;
  		if (index_i!=index_j){
  			L[j] = -index_i*L[j]; ;
            tempij=tempij*(index_j - index_i);
  		}        
  	}
  	//std::cout << L[j] << std::endl;
    //std::cout << "tempij="<<tempij << std::endl;
    if (tempij<0) tempij+=modulus;
    temptemp=tempij;
    //std::cout << "tempij="<<temptemp[0] << std::endl;
    inversotemp=temptemp.MultiplicativeInverse();
    inversotemp[0].ConvertToInt();
    //std::cout << "iii="<<inversotemp[0] << std::endl;
    inversotemp*=L[j];
    L[j] =inversotemp[0].ConvertToInt();
} 
  
  std::cout << "L" << L << std::endl;  
  
  Element b(m_params->GetTrapdoorParams()->GetElemParams(),
               Format::EVALUATION, true); 

  for (usint j=0; j<=d; j++){
  	b += b_j(0,j)*L[j];	
  }

  
/*
std::vector<float> L(d+1);  
for (usint j=0; j<=d; j++){
  	index_j = J[j];
  	L[j]=1;
  	//std::cout << "index_j " << index_j << std::endl;
  	for (usint i=0; i<=d; i++){
  		//std::cout << "L " << L << std::endl;
  		//std::cout << "J[i] " << J[i] << std::endl;
  		index_i = J[i];
  		if (index_i!=index_j){
  			//std::cout << "L " << L << std::endl;
  			L[j] = -index_i*L[j];  
  			//std::cout << "L " << L << std::endl;
  			L[j] = L[j]/(index_j - index_i);
  			//std::cout << "L " << L << std::endl;
  		}
  	}
}      

//std::cout << "L " << L << std::endl;

float pippo;
for (usint i=0; i<m_N; i++){
	pippo = 0;
	for (usint j=0; j<=d; j++){
		index_j = J[j];
		s_primo_pos=0;
	  	for (usint k=0; k<s_primo.size(); k++){
	  		if (s_primo[k]==index_j){
	  			s_primo_pos = k;
	  		}
		}
		pippo += b_j(0,j).at(i).ConvertToInt()*L[j]; 
	}
	
	b.at(i) = pippo;
}

Element none(m_params->GetTrapdoorParams()->GetElemParams(),
               Format::EVALUATION, true);
none = none+1;         

b = b*none;   
*/
  
  Element rr(m_params->GetTrapdoorParams()->GetElemParams(),
               Format::EVALUATION, true); 
            
  rr = ctext.GetC0() - b;
  
  //std::cout << rr << std::endl;
  
  dtext->SwitchFormat();
  
  typename Element::Integer dec, threshold = m_q >> 2, qHalf = m_q >> 1;
  
  //std::cout << threshold << std::endl;
  //std::cout << rr.at(0).SerializedObjectName() << std::endl;
  //std::cout << dec.SerializedObjectName() << std::endl;
  
  for (usint i = 0; i < m_N; i++) {
    dec = rr.at(i);
    if (dec > qHalf) dec = m_q - dec;
    if (dec > threshold)
      dtext->at(i) = 1;
    else
      dtext->at(i) = typename Element::Integer(0);
  }             
  
  /*
  for (usint j = 0; j < m_m; j++) *dtext += ctW(0, j) * sk(j, 0);

  usint iW = 0;
  usint iAW = 0;
  // #pragma omp parallel for
  for (usint i = 0; i < m_ell; i++) {
    if (w[i] == 1 || w[i] == -1) {
      for (usint j = 0; j < m_m; j++) *dtext += ctW(iW + 1, j) * sk(j, i + 1);
      iW++;
    } else {
      if (s[i] == 1) {
        for (usint j = 0; j < m_m; j++) *dtext += cPos(iAW, j) * sk(j, i + 1);
      } else {
        for (usint j = 0; j < m_m; j++) *dtext += cNeg(iAW, j) * sk(j, i + 1);
      }
      iAW++;
    }
  }

  *dtext = ctC1 - *dtext;
  dtext->SwitchFormat();

  typename Element::Integer dec, threshold = m_q >> 2, qHalf = m_q >> 1;
  for (usint i = 0; i < m_N; i++) {
    dec = dtext->at(i);

    if (dec > qHalf) dec = m_q - dec;
    if (dec > threshold)
      dtext->at(i) = 1;
    else
      dtext->at(i) = typename Element::Integer(0);
  }
  */
  return ptext; 
}

	Plaintext MakeCoefPackedPlaintextZZG(vector<int64_t> vectorOfInts){

		return contextZZ.MakeCoefPackedPlaintext(vectorOfInts);

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

