const { expect } = require("chai");
const { ethers } = require("hardhat");
const web3Abi = require('web3-eth-abi');
const web3 = require('web3');

describe("EIP3009", () => {
    let TokenFactory;
    let TokenContract;
    let owner;
    let alice;
    let bob;
    let ownerAddress;
    let aliceAddress;
    let bobAddress;
    let TRANSFER_WITH_AUTHORIZATION_TYPEHASH;
    let RECEIVE_WITH_AUTHORIZATION_TYPEHASH;
    let CANCEL_AUTHORIZATION_TYPEHASH;
    beforeEach(async () =>{
        [owner, alice, bob] = await ethers.getSigners();

        //deploy TestToken 
        // TestTokenFactory = await ethers.getContractFactory("TestUSDT");
        // TestTokenContract = await TestTokenFactory.deploy();
        
        //depoly VestingContract
        TokenFactory = await ethers.getContractFactory("Token");
        TokenContract = await TokenFactory.deploy("TestToken", "1", "TOK", 18, 1000000000000000 );
        //get client address
        ownerAddress = await owner.getAddress();
        aliceAddress = await alice.getAddress();
        bobAddress = await bob.getAddress();

        TRANSFER_WITH_AUTHORIZATION_TYPEHASH = web3.utils.keccak256(
            "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
          );

        RECEIVE_WITH_AUTHORIZATION_TYPEHASH = web3.utils.keccak256(
            "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
          );

        CANCEL_AUTHORIZATION_TYPEHASH = web3.utils.keccak256(
            "CancelAuthorization(address authorizer,bytes32 nonce)"
          );
    });

    
    describe("TestUSDT", () =>{
        it("BalanceOf", async () =>{
            const _balanceOf = await TokenContract.balanceOf(ownerAddress);
            console.log(_balanceOf);
            // console.log(TRANSFER_WITH_AUTHORIZATION_TYPEHASH);
            // expect(_balanceOf).to.equal(600000000000);
        });
        it("has the expected type hashes", async () => {
            expect(await TokenContract.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()).to.equal(
              TRANSFER_WITH_AUTHORIZATION_TYPEHASH
            );

            expect(await TokenContract.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()).to.equal(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH
              );
          
            expect(await TokenContract.CANCEL_AUTHORIZATION_TYPEHASH()).to.equal(
            CANCEL_AUTHORIZATION_TYPEHASH
            );
        });
        it("Mint", async()=>{
            // await TestTokenContract.connect(bob).mint(100000000);
            // const _balanceOf = await TestTokenContract.balanceOf(bobAddress);
            // // console.log(_balanceOf);
            // expect(_balanceOf).to.equal(100000000);
        });
    })

    
});