// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "../lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import "../lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract TestSwapProtocol is ERC20 {
    mapping(address => mapping(address => uint256)) public redeemMapping;
    address public owner;

    constructor() ERC20("TestSwapProtocol", "TSP") {
        owner = msg.sender;
    }

    function swap(address tokenIn, uint256 amountIn, uint256 amountOut) public {
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        _mint(msg.sender, amountOut);
        redeemMapping[msg.sender][tokenIn] += amountIn;
    }

    function redeem(address tokenIn) public {
        uint256 amountIn = redeemMapping[msg.sender][tokenIn];
        IERC20(tokenIn).transfer(msg.sender, amountIn);
        redeemMapping[msg.sender][tokenIn] = 0;
    }

    function rescueToken(address token) public {
        IERC20(token).transfer(owner, IERC20(token).balanceOf(address(this)));
    }

    function rescueETH() public {
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}

// BASE ADDRESS: 0x3bC4CCc525cBf4902125C4707d0cb172327348d9
// cast send 0x3bC4CCc525cBf4902125C4707d0cb172327348d9 --private-key $PRIVATE_KEY --rpc-url $BASE_RPC_URL "swap(address,uint256,uint256)" 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 10000 12345
// cast send 0x3bC4CCc525cBf4902125C4707d0cb172327348d9 --private-key $PRIVATE_KEY --rpc-url $BASE_RPC_URL "redeem(address)" 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

// AVALANCHE ADDRESS: 0x1a8516de1199363A8F980f2eA7D693132E4BC6c3