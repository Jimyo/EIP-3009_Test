require("dotenv").config();

require("@nomiclabs/hardhat-etherscan");
require("@nomiclabs/hardhat-waffle");
require('hardhat-contract-sizer');
require("hardhat-gas-reporter");

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task("accounts", "Prints the list of accounts", async (taskArgs, hre) => {
  const accounts = await hre.ethers.getSigners();

  for (const account of accounts) {
    console.log(account.address);
  }
});

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: "0.8.8",
  contractSizer: 
  {
    alphaSort: true,
    runOnCompile: true,
    disambiguatePaths: false,
    only: ['Greeter'],
  },
  defaultNetwork: 'hardhat',
  networks: 
  {
    hardhat: {
    },
    mumbai: 
    {
       url: process.env.POLYGON_MUMBAI_RPC_PROVIDER,
       accounts: [`0x${process.env.PRIVATE_KEY}`]
    },
    polygon:
    {
      url: process.env.POLYGON_MAIN_RPC_PROVIDER,
      accounts: [`0x${process.env.PRIVATE_KEY}`]
    }
  },
  etherscan: 
  {
    apiKey: process.env.POLYGONSCAN_API_KEY,
  },
  gasReporter: {
    currency: 'TWD',
    gasPrice: 21,
    token: 'MATIC',
    coinmarketcap: process.env.COINMARKETCAP_API_KEY
  }
};
