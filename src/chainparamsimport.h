#ifndef BITCOIN_CHAINPARAMSIMPORT_H
#define BITCOIN_CHAINPARAMSIMPORT_H


void AddImportHashesMain(std::vector<CImportedCoinbaseTxn> &vImportedCoinbaseTxns)
{
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(1,  uint256S("9f36847852e3a63aa7f95f3530b8703280f5bd278db73ee73fe074bbdcb91608")));
};
void AddImportHashesTest(std::vector<CImportedCoinbaseTxn> &vImportedCoinbaseTxns)
{
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(1,  uint256S("063cfa1fb7d022cb2c7e4a9b63f8bbc3e906d7704b7f8f423cfa4c0333d38039")));
};


#endif // BITCOIN_CHAINPARAMSIMPORT_H
