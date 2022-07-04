# Sample Hardhat Project
Hardhat 基礎設置模板

### 安裝所有依賴套件
```shell
npm install 
```
# 套件說明

|  套件名稱   | 說明  |  config  |
|  ----  | ----  | ---- |
| hardhat  | Hardhat核心 |
| hardhat-contract-sizer  | Solidity size 輔助套件 | `require('hardhat-contract-sizer');`|
| hardhat-gas-reporter | 合約呼叫Gas Fee 輔助套件 | `require("hardhat-gas-reporter");` |
| @nomiclabs/hardhat-ethers | Hardhat ether.js 集成套件 |
| @nomiclabs/hardhat-waffle | Hardhat waffle 集成套件 | `require("@nomiclabs/hardhat-waffle");` |
| @nomiclabs/hardhat-etherscan | Etherscan 驗證合約套件 | `require("@nomiclabs/hardhat-etherscan");` |
| chai | Hardhat 測試套件 |
| dotenv | 環境變數套件 | `require("dotenv").config();` |
| web3-eth-abi | Web3 ABI 套件 |
| @openzeppelin/contracts | OpenZeppelin 合約標準庫 |
| @openzeppelin/contracts-upgradeable | OpenZeppelin 升級合約標準庫 |


# 套件設定

##### hardhat-contract-sizer
hardhat.config.js
```json
contractSizer: 
  {
    alphaSort: true,
    runOnCompile: true,
    disambiguatePaths: false,
    only: ['Greeter'],
  },
```
##### hardhat-gas-reporter
hardhat.config.js
```json
gasReporter: {
    currency: 'TWD',
    gasPrice: 21,
    token: 'MATIC',
    coinmarketcap: process.env.COINMARKETCAP_API_KEY
  }
```

##### @nomiclabs/hardhat-etherscan
hardhat.config.js
```json
etherscan: {
        apiKey: process.env.POLYGONSCAN_API_KEY,
    },
```