#ifndef TRADECLIENT_H
#define TRADECLIENT_H

#include "application.h"
#include <iostream>
#include "quickfix/SocketInitiator.h"

class TradeClient
{
public:
    TradeClient* create_client(std::string filepath);
    int run();
    void put_order(std::string quoteid, std::string symbol,
                   std::string currency,
                   int side,
                   int quantity,
                   int price, int time_in_force) ;
private:
    Application* mApplication;
    FIX::Initiator* mInitiator;
};
#endif