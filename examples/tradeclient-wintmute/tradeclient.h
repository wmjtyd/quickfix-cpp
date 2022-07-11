#ifndef TRADECLIENT_H
#define TRADECLIENT_H

#include "application.h"
#include <iostream>

class TradeClient
{
public:
    TradeClient* create_client();
    void put_order(std::string quoteid, std::string symbol,
                   std::string currency,
                   int side,
                   int quantity,
                   int price, int time_in_force) ;
private:

};
#endif