use utils::{
    alloy::{
        hex::FromHex,
        primitives::{address, Address, Bytes, FixedBytes, U256},
        providers::Provider,
        sol,
    },
    circle::get_circle_message_v1,
    web3::{get_provider, get_wallet, increase_allowence},
    wormhole::get_vaa,
    *,
};
use MayanSwift::OrderParams;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MayanSwift,
    "../assets/MayanSwift.json"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (address, wallet) = utils::web3::get_wallet()?;
    println!("Wallet Address: {}", address);
    let mut bytes_address = [0u8; 32];
    bytes_address[12..].copy_from_slice(address.as_slice());

    let sepolia_provider = utils::web3::get_provider(&wallet, "https://ethereum-sepolia-rpc.publicnode.com")?;
    // https://testnet-rpc.monad.xyz

    println!(
        "Sepolia Latest Block: {:?}",
        sepolia_provider.get_block_number().await?
    );

    let mayan_swift_address = address!("0x66c928b540fCd3456597C5e2B9968ef9353E0F66");
    let mayan_swift =
        MayanSwift::new(mayan_swift_address, sepolia_provider.clone());

    let tx = mayan_swift
        .createOrderWithEth(
            OrderParams {
                auctionMode: 1,
                referrerBps: 0,
                cancelFee: 10000,
                deadline: 1844036752,
                gasDrop: 0,
                minAmountOut: 10000,
                refundFee: 10000,
                trader: bytes_address.try_into()?,
                destChainId: 1,
                tokenOut: [0u8; 32].try_into()?,
                // destAddr: bytes_address.try_into()?,
                destAddr: FixedBytes::<32>::from_hex("34cdc6b2623f36d60ae820e95b60f764e81ec2cd3b57b77e3f8e25ddd43ac373")?,
                referrerAddr: [0u8; 32].try_into()?,
                random: [0u8; 32].try_into()?,
            },
        )
        .value(U256::from(10000000000000000u64))
        .send()
        .await?;
    let receipt = tx.watch().await?;
    println!("MayanSwift Create Order Receipt: {:?}", receipt);

    Ok(())
}
