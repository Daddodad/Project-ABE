#ifndef UTILS_H
#define UTILS_H

#include <memory>
#include <vector>
#include <random>
#include <abecontext.h>

long int reciproco(long int num, long int modulo){
    std::vector<long int> esponenti;
    int esponente=0;
    std::cout << modulo;
    while(pow(2,esponente)<modulo){
        esponente++;
        std::cout << esponente;
    }
    esponente=esponente-1;
    while(esponente>=1){
        if(pow(2,esponente)<modulo){ 
            esponenti.push_back(esponente);
            modulo-=pow(2,esponente);
            esponente++;}
    }
    //std::cout << "esponenti " << esponenti;
    return 1;
}

#endif
