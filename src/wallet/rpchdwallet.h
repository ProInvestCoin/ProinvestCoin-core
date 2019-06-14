// Copyright (c) 2017 The ProInvestCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPCHDWALLET_H
#define BITCOIN_WALLET_RPCHDWALLET_H

namespace interfaces {
class Chain;
class Handler;
}

void RegisterHDWalletRPCCommands(interfaces::Chain& chain, std::vector<std::unique_ptr<interfaces::Handler>>& handlers);

#endif //BITCOIN_WALLET_RPCHDWALLET_H
