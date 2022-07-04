/* -*- C++ -*- */

/****************************************************************************
** Copyright (c) 2001-2014
**
** This file is part of the QuickFIX FIX Engine
**
** This file may be distributed under the terms of the quickfixengine.org
** license as defined by quickfixengine.org and appearing in the file
** LICENSE included in the packaging of this file.
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** See http://www.quickfixengine.org/LICENSE for licensing information.
**
** Contact ask@quickfixengine.org if any conditions of this licensing are
** not clear to you.
**
****************************************************************************/

#ifdef _MSC_VER
#pragma warning( disable : 4503 4355 4786 )
#endif
#undef max
#undef min
#define NOMINMAX 1
#include "quickfix/config.h"
#include "Application.h"
#include "quickfix/Session.h"
//#include <jwt-cpp/jwt.h>
#include "jwt/jwt.hpp"
#include <picojson/picojson.h>
#include <iostream>
#include <openssl/sha.h>
#include <random>

//config
std::string ACCOUNT_ID = "";
std::string SECRET_KEY_ID = "";
std::string SECRET_KEY = "";
std::string SYMBOL = "BTCUSDT";
std::string VENUE = "GBBO";  // choose exchange you want to trade
std::string SERVER = "fix.api.apifiny.com:1443";  //#use the right endpoint for each exchange
std::string SenderCompID = ACCOUNT_ID;
std::string TargetCompID = "APIFINY";

//const std::string __SOH__2 = "";
const std::string __SOH__ = std::string("\x01");
void replace_str(std::string& str, const std::string& before, const std::string& after)
{
    for (std::string::size_type pos(0); pos != std::string::npos; pos += after.length())
    {
        pos = str.find(before, pos);
        if (pos != std::string::npos)

            str.replace(pos, before.length(), after);
        else
            break;
    }
}

std::string sha256(const std::string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string getSignature(std::string method, 
                         std::string account_id, 
                         std::string secret_key_id,
                         std::string params, 
                         std::string secret_key) {
    /*std::cout << "c++:" << std::endl;
    std::cout << "method:" << method << std::endl;
    std::cout << "account_id:" << account_id << std::endl;
    std::cout << "secret_key_id:" << secret_key_id << std::endl;
    std::cout << "params:" << params << std::endl;
    std::cout << "secret_key:" << secret_key << std::endl;*/
    
    auto digest = sha256(params);
    //std::cout << "digest:" << digest << std::endl;
    std::time_t now = std::time(NULL);
    std::tm* ptm = std::localtime(&now);
    std::chrono::system_clock::time_point exp = std::chrono::system_clock::from_time_t(1656559384);
    /*auto token = jwt::create()
        //.set_issuer("auth0")
        //.set_type("JWS")

        .set_payload_claim("accountId", jwt::claim(std::string(account_id)))
        .set_payload_claim("secretKeyId", jwt::claim(std::string(secret_key_id)))
        .set_payload_claim("digest", jwt::claim(std::string(digest)))
        .set_payload_claim("method", jwt::claim(std::string(method)))
        //.set_payload_claim("exp", jwt::claim(std::chrono::system_clock::now() + std::chrono::seconds{ 36000 }))

        //.set_issued_at(std::chrono::system_clock::now())
        //.set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{ 300 })
        .set_expires_at(exp)
        .sign(jwt::algorithm::hs256{ secret_key });
        std::cout << "token:" << token << std::endl;
    */
    using namespace jwt::params;
    //auto key = "secret"; //Secret to use for the algorithm
    //Create JWT object
    jwt::jwt_object obj{ 
        algorithm("HS256"), 
        payload({
            {"accountId", account_id},
            {"secretKeyId", secret_key_id},
            {"digest", digest},
            {"method", method}         
        }),
        secret(secret_key) };
    obj.add_claim("exp", std::chrono::system_clock::now() + std::chrono::seconds{ 300 });

    //Get the encoded string/assertion
    auto enc_str = obj.signature();
    //std::cout << "enc_str: " << enc_str << std::endl;

    //
    //auto dec_obj = jwt::decode(enc_str, algorithms({ "HS256" }), secret(secret_key));
    //std::cout << "dec_obj.header():" << dec_obj.header() << std::endl;
    //std::cout << "dec_obj.payload():" << dec_obj.payload() << std::endl;
    //jwt::jwt_object obj{ algorithm("HS256"), payload({{"some", "payload"}}), secret("secret")};
    
    auto token = enc_str;

    return token;
}

static void split(const std::string& s, std::vector<std::string>& tokens, const std::string& delimiters = " ")
{
    std::string::size_type lastPos = s.find_first_not_of(delimiters, 0);
    std::string::size_type pos = s.find_first_of(delimiters, lastPos);
    while (std::string::npos != pos || std::string::npos != lastPos) {
        tokens.push_back(s.substr(lastPos, pos - lastPos));
        lastPos = s.find_first_not_of(delimiters, pos);
        pos = s.find_first_of(delimiters, lastPos);
    }
}

std::string generate_order_id(std::string accountId)
{
    std::vector<std::string> result;
    split(accountId, result, "-");

    //orderId if requested, should be composed of: account number + random number + 13 digit timestamp+3 digit random number. 
    //Up to 64 digits.
    
    //std::cout << "split:" << result[1] << std::endl
    std::cout << "now:" << std::chrono::system_clock::now().time_since_epoch().count()/1000 << std::endl;
    //std::cout << "now:" << std::chrono::system_clock::now().time_since_epoch().count() / std::chrono::micro << std::endl;
    auto currentTime = std::chrono::system_clock::now().time_since_epoch().count() / 10000;
    std::random_device rd;
    auto r = rd();
    auto randomDigit = (r % 900) + 100;
    std::cout << "countid:" << result[1] << std::endl;
    std::cout << "currentTime:" << currentTime << std::endl;
    std::cout << "randomDigit:" << randomDigit << std::endl;
    std::string orderId = result[1] + std::to_string(currentTime) + std::to_string(randomDigit);
    std::cout << "orderId:" << orderId << std::endl;
    return orderId;
    
}

void Application::onCreate( const FIX::SessionID& sessionID)
{
    std::cout << std::endl << "onCreate - " << sessionID << std::endl;
}

void Application::onLogon( const FIX::SessionID& sessionID )
{
  std::cout << std::endl << "Logon - " << sessionID << std::endl;
}

void Application::onLogout( const FIX::SessionID& sessionID )
{
  std::cout << std::endl << "Logout - " << sessionID << std::endl;
}

void Application::toAdmin( FIX::Message& message, const FIX::SessionID& sessionID)
{
	//std::cout << std::endl << "toAdmin - " << sessionID << std::endl;
	//std::cout << std::endl << "toAdmin: " << message << std::endl;
    
    if (message.getHeader().getField(FIX::FIELD::MsgType) == "A")
    {
        std::string method = "Fix";
        std::string account_id = ACCOUNT_ID;
        std::string secret_key_id = SECRET_KEY_ID;
        std::string params = ACCOUNT_ID;
        std::string secret_key = SECRET_KEY;
        auto signature = getSignature(method,
            account_id,
            secret_key_id,
            params,
            secret_key);

        message.setField(FIX::Username("xxx"));
        message.setField(FIX::Password("xxx"));

        if (true == message.isSetField(FIX::FIELD::ResetSeqNumFlag))
        {
            std::cout << "Sending admin: Logging in user" << message.getHeader().getField(FIX::FIELD::Username)
                << "reset seq" << message.getHeader().getField(FIX::FIELD::ResetSeqNumFlag)
                << "at" << message.getHeader().getField(FIX::FIELD::SendingTime)
                << "seq" << message.getHeader().getField(FIX::FIELD::MsgSeqNum)
                << "for session" << sessionID << std::endl;
        }
        else 
        {
            std::cout << "Sending admin: Logging in user" << message.getHeader().getField(FIX::FIELD::Username)               
                << "at" << message.getHeader().getField(FIX::FIELD::SendingTime)
                << "seq" << message.getHeader().getField(FIX::FIELD::MsgSeqNum)
                << "for session" << sessionID << std::endl;
        }
        //std::cout << "signature:" << signature << std::endl;
    }

    std::string m = message.toString();
    replace_str(m, __SOH__, "|");
    //std::cout << std::endl
    //<< "toAdmin: " << m << std::endl;
}

void Application::fromAdmin( const FIX::Message& message, const FIX::SessionID& sessionID)
EXCEPT( FIX::FieldNotFound, FIX::IncorrectDataFormat, FIX::IncorrectTagValue, FIX::RejectLogon ) 
{
	std::cout << std::endl << "fromAdmin - " << sessionID << std::endl;
	//std::cout << std::endl << "fromAdmin: " << message << std::endl;
    std::string m = message.toString();
    replace_str(m, __SOH__, "|");
    std::cout << std::endl << "fromAdmin: " << m << std::endl;
}


void Application::fromApp( const FIX::Message& message, const FIX::SessionID& sessionID )
EXCEPT( FIX::FieldNotFound, FIX::IncorrectDataFormat, FIX::IncorrectTagValue, FIX::UnsupportedMessageType )
{
  crack( message, sessionID );
  //std::cout << std::endl << "IN: " << message << std::endl;
  std::string m = message.toString();
  replace_str(m, __SOH__, "|");
  std::cout << std::endl << "IN: " << m << std::endl;
}

void Application::toApp( FIX::Message& message, const FIX::SessionID& sessionID )
EXCEPT( FIX::DoNotSend )
{
    std::cout << std::endl << "toApp: " << sessionID << std::endl;
  try
  {
    FIX::PossDupFlag possDupFlag;
    message.getHeader().getField( possDupFlag );
    if ( possDupFlag ) throw FIX::DoNotSend();
  }
  catch ( FIX::FieldNotFound& ) {}

  std::string m = message.toString();
  //replace_str(&m, __SOH__, "|");
  replace_str(m, __SOH__, "|");
  std::cout << std::endl
  << "OUT: " << m << std::endl;
}


// Quote Response
void Application::onMessage
( const FIX44::Quote&, const FIX::SessionID& ) {}
// MarketDataSnapshotFullRefresh
void Application::onMessage
( const FIX44::MarketDataSnapshotFullRefresh&, const FIX::SessionID& ) {}
// ExecutionReport
( const FIX44::ExecutionReport&, const FIX::SessionID& ) {
    std::cout << std::endl
    << "onMessage: FIX::SessionID:" << sessionId << std::endl
    << "onMessage: FIX42::ExecutionReport:" << executionReport << std::endl;
}
// OrderCancelReject
void Application::onMessage
( const FIX44::OrderCancelReject&, const FIX::SessionID& ) {}
// PositionReport
void Application::onMessage
( const FIX44::PositionReport&, const FIX::SessionID& ) {}
// SecurityList
void Application::onMessage
( const FIX50::OrderCancelReject&, const FIX::SessionID& ) {}

void Application::run()
{
  while ( true )
  {
    try
    {
      char action = queryAction();
    }
    catch ( std::exception & e )
    {
      std::cout << "Message Not Sent: " << e.what();
    }
  }
}

void Application::queryHeader( FIX::Header& header )
{
  header.setField( querySenderCompID() );
  header.setField( queryTargetCompID() );

  if ( queryConfirm( "Use a TargetSubID" ) )
    header.setField( queryTargetSubID() );
}

char Application::queryAction()
{
  char value;
  std::cout << std::endl
  << "1) Enter Order" << std::endl
  << "2) Cancel Order" << std::endl
  << "3) Replace Order" << std::endl
  << "4) Market data test" << std::endl
  << "5) test" << std::endl
  << "6) Quit" << std::endl
  << "Action: ";
  std::cin >> value;
  switch ( value )
  {
    case '1': case '2': case '3': case '4': case '5': case '6': break;
    default: throw std::exception();
  }
  return value;
}

int Application::queryVersion()
{
  char value;
  std::cout << std::endl
  << "1) FIX.4.0" << std::endl
  << "2) FIX.4.1" << std::endl
  << "3) FIX.4.2" << std::endl
  << "4) FIX.4.3" << std::endl
  << "5) FIX.4.4" << std::endl
  << "6) FIXT.1.1 (FIX.5.0)" << std::endl
  << "BeginString: ";
  std::cin >> value;
  switch ( value )
  {
    case '1': return 40;
    case '2': return 41;
    case '3': return 42;
    case '4': return 43;
    case '5': return 44;
    case '6': return 50;
    default: throw std::exception();
  }
}

bool Application::queryConfirm( const std::string& query )
{
  std::string value;
  std::cout << std::endl << query << "?: ";
  std::cin >> value;
  return toupper( *value.c_str() ) == 'Y';
}

FIX::SenderCompID Application::querySenderCompID()
{
  std::string value;
  std::cout << std::endl << "SenderCompID: ";
  std::cin >> value;
  return FIX::SenderCompID( value );
}

FIX::TargetCompID Application::queryTargetCompID()
{
  std::string value;
  std::cout << std::endl << "TargetCompID: ";
  std::cin >> value;
  return FIX::TargetCompID( value );
}

FIX::TargetSubID Application::queryTargetSubID()
{
  std::string value;
  std::cout << std::endl << "TargetSubID: ";
  std::cin >> value;
  return FIX::TargetSubID( value );
}

FIX::ClOrdID Application::queryClOrdID()
{
  std::string value;
  std::cout << std::endl << "ClOrdID: ";
  std::cin >> value;
  return FIX::ClOrdID( value );
}

FIX::OrigClOrdID Application::queryOrigClOrdID()
{
  std::string value;
  std::cout << std::endl << "OrigClOrdID: ";
  std::cin >> value;
  return FIX::OrigClOrdID( value );
}

FIX::Symbol Application::querySymbol()
{
  std::string value;
  std::cout << std::endl << "Symbol: ";
  std::cin >> value;
  return FIX::Symbol( value );
}

FIX::Side Application::querySide()
{
  char value;
  std::cout << std::endl
  << "1) Buy" << std::endl
  << "2) Sell" << std::endl
  << "3) Sell Short" << std::endl
  << "4) Sell Short Exempt" << std::endl
  << "5) Cross" << std::endl
  << "6) Cross Short" << std::endl
  << "7) Cross Short Exempt" << std::endl
  << "Side: ";

  std::cin >> value;
  switch ( value )
  {
    case '1': return FIX::Side( FIX::Side_BUY );
    case '2': return FIX::Side( FIX::Side_SELL );
    case '3': return FIX::Side( FIX::Side_SELL_SHORT );
    case '4': return FIX::Side( FIX::Side_SELL_SHORT_EXEMPT );
    case '5': return FIX::Side( FIX::Side_CROSS );
    case '6': return FIX::Side( FIX::Side_CROSS_SHORT );
    case '7': return FIX::Side( 'A' );
    default: throw std::exception();
  }
}

FIX::OrderQty Application::queryOrderQty()
{
  long value;
  std::cout << std::endl << "OrderQty: ";
  std::cin >> value;
  return FIX::OrderQty( value );
}

FIX::OrdType Application::queryOrdType()
{
  char value;
  std::cout << std::endl
  << "1) Market" << std::endl
  << "2) Limit" << std::endl
  << "3) Stop" << std::endl
  << "4) Stop Limit" << std::endl
  << "OrdType: ";

  std::cin >> value;
  switch ( value )
  {
    case '1': return FIX::OrdType( FIX::OrdType_MARKET );
    case '2': return FIX::OrdType( FIX::OrdType_LIMIT );
    case '3': return FIX::OrdType( FIX::OrdType_STOP );
    case '4': return FIX::OrdType( FIX::OrdType_STOP_LIMIT );
    default: throw std::exception();
  }
}

FIX::Price Application::queryPrice()
{
  double value;
  std::cout << std::endl << "Price: ";
  std::cin >> value;
  return FIX::Price( value );
}

FIX::StopPx Application::queryStopPx()
{
  double value;
  std::cout << std::endl << "StopPx: ";
  std::cin >> value;
  return FIX::StopPx( value );
}

FIX::TimeInForce Application::queryTimeInForce()
{
  char value;
  std::cout << std::endl
  << "1) Day" << std::endl
  << "2) IOC" << std::endl
  << "3) OPG" << std::endl
  << "4) GTC" << std::endl
  << "5) GTX" << std::endl
  << "TimeInForce: ";

  std::cin >> value;
  switch ( value )
  {
    case '1': return FIX::TimeInForce( FIX::TimeInForce_DAY );
    case '2': return FIX::TimeInForce( FIX::TimeInForce_IMMEDIATE_OR_CANCEL );
    case '3': return FIX::TimeInForce( FIX::TimeInForce_AT_THE_OPENING );
    case '4': return FIX::TimeInForce( FIX::TimeInForce_GOOD_TILL_CANCEL );
    case '5': return FIX::TimeInForce( FIX::TimeInForce_GOOD_TILL_CROSSING );
    default: throw std::exception();
  }
}

void Application::put_quote(FIX::Symbol, FIX::Currency currency, FIX::Side side, FIX::OrderQty quantity)
{
    FIX44::QuoteRequest quoteRequest(FIX::QuoteReqID("ddd"));
    quoteRequest.set( FIX::Symbol( "BTC/USDT" ) );
    quoteRequest.set( FIX::Side( FIX::Side_BUY ) );
    quoteRequest.set( FIX::OrderQty( 1 ) );

    FIX::Session::sendToTarget( quoteRequest );
}

void Application::put_order(FIX::QuoteID quoteid, FIX::Symbol symbol, FIX::Currency currency,
    FIX::Side side, FIX::OrderQty quantity, FIX::Price price, FIX::TimeInForce time_in_force)
{

//    msg.setField(fix.ClOrdID(str(self.__genOrderID()))) #11=Unique order
//    if quoteid:
//        msg.setField(fix.QuoteID(quoteid))
//    msg.setField(fix.Symbol(symbol)) #55
//    if currency:
//        msg.setField(fix.Currency(currency))
//    msg.setField(fix.Side(side)) #54=1 Buy
//    msg.setField(fix.Price(price))
//    msg.setField(fix.TimeInForce(time_in_force))
//    msg.setField(fix.OrderQty(quantity)) #38=100
//    fix.Session.sendToTarget(msg, self.__sessionID)

    auto nowUtc = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::cout << "order utc:" << nowUtc << std::endl;
    //std::chrono::system_clock::now();
    //FIX::DateTime();
    auto orderId = generate_order_id(ACCOUNT_ID);
    FIX::OrdType ordType;
    std::cout << "orderId:" << orderId << std::endl;
    FIX44::NewOrderSingle newOrderSingle();
    newOrderSingle.set( quoteid );
    newOrderSingle.set( symbol );
    newOrderSingle.set( side );
    newOrderSingle.set( price );
    newOrderSingle.set( time_in_force );
    newOrderSingle.set( FIX::OrderQty( 1 ) );

    FIX::Session::sendToTarget( newOrderSingle );
}
//def put_subscribe(self, symbol:str, subscribe : bool) 
void Application::put_subscribe(FIX::Symbol symbol, bool subscribe)
{
//    msg = fix.Message()
//    msg.setField(fix.MDReqID(str(self.__genMDReqID())))
//    msg.setField(fix.Symbol(symbol)) #55
//    msg.setField(fix.SubscriptionRequestType('1' if subscribe else '0'))
//    fix.Session.sendToTarget(msg, self.__sessionID)

    FIX44::MarketDataRequest marketDataRequest();
    marketDataRequest.set( FIX::MDReqID( 1 ) );
    marketDataRequest.set( symbol );
    marketDataRequest.set( FIX:SubscriptionRequestType('1') if subscribe else FIX:SubscriptionRequestType('0') );
    FIX::Session::sendToTarget( newOrderSingle );
}

// def put_position(self, currency:str, zeroPositions:bool, subscribe:bool):
void Application::put_position(FIX::Currency currency, bool zeroPositions, bool subscribe)
{
//    msg = fix.Message()
//    msg.setField(fix.PosReqID(str(self.__genPosReqID())))
//    msg.setField(fix.SubscriptionRequestType('1' if subscribe else '0'))
//    msg.setField(fix.Currency(currency))
//    msg.setField(fix.BoolField(100551, zeroPositions)) # ZeroPositions
//    fix.Session.sendToTarget(msg, self.__sessionID)

    FIX44::RequestForPositions requestForPositions();
    marketDataRequest.set( FIX::PosReqID( 1 ) );
    marketDataRequest.set( currency );
    marketDataRequest.set( FIX::SubscriptionRequestType('1') if subscribe else FIX::SubscriptionRequestType('0') );
    marketDataRequest.set( FIX::BoolField(100551, zeroPositions));
    FIX::Session::sendToTarget( newOrderSingle );
}

// def put_security(self, symbol:str):
void Application::put_security(FIX::Symbol symbol)
{
//    msg.getHeader().setField(fix.MsgType(fix.MsgType_SecurityListRequest)) #39=x
//    msg.setField(fix.SecurityReqID(str(self.__genSecurityReqID())))
//    if symbol:
//        msg.setField(fix.Symbol(symbol)) #55
//    fix.Session.sendToTarget(msg, self.__sessionID)

    FIX44::SecurityListRequest securityListRequest();
    marketDataRequest.set( FIX::SecurityReqID( 1 ) );
    marketDataRequest.set( symbol );
    FIX::Session::sendToTarget( securityListRequest );
}

//def put_change_password(self, change_username, old_password, new_password):
void Application::put_change_password(FIX::Username change_username, FIX::Password old_password, FIX::Password new_password)
{
//    msg.setField(fix.UserRequestID(str(self.__genUserReqID())))
//    msg.setField(fix.UserRequestType(3)) # change password
//    msg.setField(fix.Username(change_username))
//    msg.setField(fix.Password(old_password))
//    msg.setField(fix.NewPassword(new_password))
//    fix.Session.sendToTarget(msg, self.__sessionID)

    FIX44::UserRequest userRequest();
    userRequest.set( FIX::UserRequestID( 1 ) );
    userRequest.set( FIX::UserRequestType( 3 ) );
    userRequest.set( change_username );
    userRequest.set( old_password );
    userRequest.set( new_password );

    FIX::Session::sendToTarget( securityListRequest );
}

//def triger_logon_out(self):
void Application::triger_logon_out()
{
//    msg.getHeader().setField(fix.MsgType(fix.MsgType_Logout)) #35=5
//    fix.Session.sendToTarget(msg, self.__sessionID)
    FIX44::Logout logout();
    FIX::Session::sendToTarget( logout );
}