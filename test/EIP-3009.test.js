const { expect } = require("chai");
const { ethers } = require("hardhat");
const web3Abi = require('web3-eth-abi');
const web3 = require('web3');
const ethereumjs = require('ethereumjs-util');


var TRANSFER_WITH_AUTHORIZATION_TYPEHASH = web3.utils.keccak256(
    "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
);

var RECEIVE_WITH_AUTHORIZATION_TYPEHASH = web3.utils.keccak256(
    "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
);

var CANCEL_AUTHORIZATION_TYPEHASH = web3.utils.keccak256(
    "CancelAuthorization(address authorizer,bytes32 nonce)"
);


describe("EIP3009", () => {
    let TokenFactory;
    let TokenContract;
    let owner;
    let alice;
    let bob;
    let ownerAddress;
    let aliceAddress;
    let bobAddress;
    // let TRANSFER_WITH_AUTHORIZATION_TYPEHASH;
    // let RECEIVE_WITH_AUTHORIZATION_TYPEHASH;
    // let CANCEL_AUTHORIZATION_TYPEHASH;
    let domainSeparator;
    let nonce ;
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

        domainSeparator = await TokenContract.DOMAIN_SEPARATOR();
        nonce = web3.utils.randomHex(32);
        // const data = TRANSFER_WITH_AUTHORIZATION_TYPEHASH;
        // var signature = await owner.signMessage(ethers.utils.arrayify(data));
        // signature = signature.substring(2);
        // console.log(signature);
        // console.log(signature.slice(0, 64));
        // console.log(signature.substring(0, 64));
        // console.log(signature.substring(64, 128));
        
        // console.log("[from]", ownerAddress);
        // console.log("[to]", "0x00");
        // console.log("[value]", 1);
        // console.log("[valldAfter]", 1657011572);
        // console.log("[valldBefore]",1657010572);
        // console.log("[value]", 1);
        // console.log("[nonce]", web3.utils.randomHex(32));
        // console.log("[v]", parseInt(signature.substring(128, 130), 16));
        // console.log("[r]", "0x"+ signature.substring(0, 64));
        // console.log("[s]", "0x" + signature.substring(64, 128));
        // console.log(ownerAddress);
        // console.log(ethers.utils.verifyMessage(ethers.utils.arrayify(data), "0x"+signature));

        // console.log(owner.address);
        
    });
    
    describe("transferWithAuthorization", () => {
        const transferParams = {
            from: ownerAddress,
            to: bobAddress,
            value: 5000,
            validAfter: 0,
            validBefore: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          };

          it("executes a transfer when a valid authorization is given", async () => {
              
            const _balanceOf = await TokenContract.balanceOf(ownerAddress);
            console.log(_balanceOf);

              let { from, to, value, validAfter, validBefore } = transferParams;
              from = ownerAddress;
              to = bobAddress;
            console.log(from, to, value, validAfter, validBefore);
            // console.log(ecsign);
            // console.log(ethers.utils.ecSign("123", "123"));
            // const a = web3.signTransferAuthorization( 
            //     from,
            //     to,
            //     value,
            //     validAfter,
            //     validBefore,
            //     nonce,
            //     domainSeparator,
            //     owner.key);
            // console.log(owner);
            
            // console.log(ecsign(Buffer.from('ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', 'hex'), Buffer.from('ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', 'hex')));
            
            console.log("[Owner]", owner);
            const SignData = "ef530f860cd8b844464424a71f46ef7d5e5e40e35b50f63c641d79343fff5fb4";
            var signature = await owner.signMessage(ethers.utils.arrayify( "0x1901" +SignData));
            console.log("[signature]", signature);
            let sig = ethers.utils.splitSignature(signature);
            console.log("[sig]", sig.v, sig.r, sig.s);

            const { v, r, s } = ethereumjs.ecsign(Buffer.from(SignData, 'hex'), Buffer.from("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", 'hex'));
            console.log("[ecsign]", v, "0x" + r.toString("hex"), "0x" + s.toString("hex"));
            const ECsignature = ethereumjs.toRpcSig(v, r, s );
            console.log("[ECsignature]", ECsignature);

            
            console.log(ethers.utils.verifyMessage(ethers.utils.arrayify("0x" +SignData), signature));
            console.log(ethers.utils.verifyMessage(ethers.utils.arrayify("0x" +SignData), ECsignature));

            return;


            // var {result, data}  = await signTransferAuthorizationTest(
            //     from,
            //     to,
            //     value,
            //     validAfter,
            //     validBefore,
            //     nonce,
            //     domainSeparator,
            //     owner
            //   );

            // console.log("[Result]",result);
            // console.log("[Data]", data);
            // console.log("[Owner Address]", ownerAddress);
            // console.log(ethers.utils.verifyMessage(ethers.utils.arrayify(data), result.compact));

            // result = result.substring(2);
            // const v = parseInt(result.substring(128, 130), 16);
            // const r = "0x" + result.substring(0, 64);
            // const s = "0x" + result.substring(64, 128);
            // console.log("[1]" ,result.v,result.r,result.s);

            const { v2, r2, s2 }  = signTransferAuthorization(
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce,
                domainSeparator,
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
              );
              
              console.log("[2]" ,v2,r2,s2);

            //   const b = signTransferAuthorization(
            //     from,
            //     to,
            //     value,
            //     validAfter,
            //     validBefore,
            //     nonce,
            //     domainSeparator,
            //     "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            //   );
              
            //   console.log("[3]" ,b.v2,b.r2,b.s2);
            // console.log("[2]" ,v2,r2,s2);
            //   console.log(await TokenContract.authorizationState(from, nonce));

              const resulta = await TokenContract.transferWithAuthorization(
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce,
                v2,
                r2,
                s2
              );
              console.log(resulta.data);

            // const data = TRANSFER_WITH_AUTHORIZATION_TYPEHASH;
            // console.log(data);
            // // var signature = await owner.signMessage(ethers.utils.arrayify(data));
            // // console.log(signature);
            //   var signature = await owner.signMessage(ethers.utils.arrayify(TRANSFER_WITH_AUTHORIZATION_TYPEHASH));
            // console.log(ethers.utils.verifyMessage(ethers.utils.arrayify(result.data), signature));
            console.log(await TokenContract.balanceOf(ownerAddress));
            console.log(await TokenContract.balanceOf(bobAddress));
          });

    });
    
    
    describe("TestUSDT", () =>{
        it("BalanceOf", async () =>{
            // const _balanceOf = await TokenContract.balanceOf(ownerAddress);
            // console.log(_balanceOf);
            // console.log(TRANSFER_WITH_AUTHORIZATION_TYPEHASH);
            // expect(_balanceOf).to.equal(600000000000);
        });
        
        it("Mint", async()=>{
            // await TestTokenContract.connect(bob).mint(100000000);
            // const _balanceOf = await TestTokenContract.balanceOf(bobAddress);
            // // console.log(_balanceOf);
            // expect(_balanceOf).to.equal(100000000);
        });
    })

    
});

function strip0x(v) {
    return v.replace(/^0x/, "");
  }

function prepend0x(v) {
return v.replace(/^(0x)?/, "0x");
}

function signTransferAuthorization(
    from,
    to,
    value,
    validAfter,
    validBefore,
    nonce,
    domainSeparator,
    privateKey
  ) {
    return signEIP712(
      domainSeparator,
      TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
      ["address", "address", "uint256", "uint256", "uint256", "bytes32"],
      [from, to, value, validAfter, validBefore, nonce],
      privateKey
    );
  
  }

  function signEIP712(
    domainSeparator,
    typeHash,
    types,
    parameters,
    privateKey
  ) {
    const digest = web3.utils.keccak256(
      "0x1901" +
        strip0x(domainSeparator) +
        strip0x(
          web3.utils.keccak256(
            web3Abi.encodeParameters(
              ["bytes32", ...types],
              [typeHash, ...parameters]
            )
          )
        )
    );
  
    console.log("[舊的的D]",digest);
    console.log("0x1901" +
    strip0x(domainSeparator) +
    strip0x(
      web3.utils.keccak256(
        web3Abi.encodeParameters(
          ["bytes32", ...types],
          [typeHash, ...parameters]
        )
      )
    ));
            // console.log("[v]", parseInt(signature.substring(128, 130), 16));
        // console.log("[r]", "0x"+ signature.substring(0, 64));
        // console.log("[s]", "0x" + signature.substring(64, 128));
    // return {v:parseInt(signature.substring(128, 130), 16)  };
    // console.log("[signEIP712 privateKey]", privateKey);
    // console.log("[舊的的sig]", ecsign(Buffer.from(digest.substring(2), 'hex'), Buffer.from(privateKey.substring(2), 'hex')));
    const { v, r, s } = ethereumjs.ecsign(Buffer.from(digest.substring(2), 'hex'), Buffer.from(privateKey.substring(2), 'hex'));
    return { v2:v, r2: "0x" + r.toString("hex"), s2: "0x" + s.toString("hex") };
  }



  async function signTransferAuthorizationTest(
    from,
    to,
    value,
    validAfter,
    validBefore,
    nonce,
    domainSeparator,
    owner
  ) {
    return await signEIP712Test(
        domainSeparator,
        TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
        ["address", "address", "uint256", "uint256", "uint256", "bytes32"],
        [from, to, value, validAfter, validBefore, nonce],
        owner
      );
  }

 async function signEIP712Test(
    domainSeparator,
    typeHash,
    types,
    parameters,
    owner
  ) {
    // const digest = web3.utils.keccak256(
    //   "0x1901" +
    //     strip0x(domainSeparator) +
    //     strip0x(
    //       web3.utils.keccak256(
    //         web3Abi.encodeParameters(
    //           ["bytes32", ...types],
    //           [typeHash, ...parameters]
    //         )
    //       )
    //     )
    // );

    const digest = ethers.utils.id(
        "0x1901" +
          strip0x(domainSeparator) +
          strip0x(
            web3.utils.keccak256(
              web3Abi.encodeParameters(
                ["bytes32", ...types],
                [typeHash, ...parameters]
              )
            )
          )
      );

    
    let flatSig = await owner.signMessage(ethers.utils.arrayify(digest))
    let sig = ethers.utils.splitSignature(flatSig);
    console.log("[新的D]",digest);
    console.log("0x1901" +
    strip0x(domainSeparator) +
    strip0x(
      web3.utils.keccak256(
        web3Abi.encodeParameters(
          ["bytes32", ...types],
          [typeHash, ...parameters]
        )
      )
    ));
    // console.log("[新的sig]", sig);
    return { result :sig, data : digest};
    console.log(privateKey);
    const { v, r, s } = ecsign(Buffer.from(digest.substring(2), 'hex'), Buffer.from(privateKey.substring(2), 'hex'));
    return { v, r: "0x" + r.toString("hex"), s: "0x" + s.toString("hex") };
  }