#ifndef ABE_ABECONTEXTZZG_H
#define ABE_ABECONTEXTZZG_H

#include <memory>
#include <vector>

#include "abeparamset.h"
#include "cpabe.h"
#include "ibe.h"
#include "abecontext.h"
#include "abecore.h"

namespace lbcrypto {
/**
 *@brief Context class for ABE schemes, including IBE and CPABE
 *@tparam Element ring element
 */
template <class Element>
class ABEContextZZG : public ABEContext<Element> {
 public:
    //Distruttore di Default
    ~ABEContextZZG() {}
    //Costruttore di Default
    ABEContextZZG() {}

    void Stampa_ciao();

}  // namespace lbcrypto

#endif
