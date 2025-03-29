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
use ITokenRouter::OrderResponse;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ITokenRouter,
    "../assets/IWormholeTokenRouter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IERC20,
    "../assets/IERC20.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MayanSwapLayer,
    "../assets/MayanSwapLayer.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IWormhole,
    "../assets/IWormhole.json"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (address, wallet) = utils::web3::get_wallet()?;
    println!("Wallet Address: {}", address);
    let mut bytes_address = [0u8; 32];
    bytes_address[12..].copy_from_slice(address.as_slice());

    let avalanche_provider = utils::web3::get_provider(&wallet, "https://avalanche.drpc.org")?;

    println!(
        "Avalanche Latest Block: {:?}",
        avalanche_provider.get_block_number().await?
    );

    let mayan_swap_layer_address = address!("0x0e689e83E1337037D9bF3A8691A06BD308c78484");
    let mayan_swap_layer =
        MayanSwapLayer::new(mayan_swap_layer_address, avalanche_provider.clone());
    let local_token = mayan_swap_layer.localToken().call().await?._0;
    println!("Local Token: {:?}", local_token);
    println!("MayanSwapLayer Address: {:?}", mayan_swap_layer_address);

    let value_u64 = 100000000;
    let value = U256::from(value_u64);
    let tx = utils::web3::increase_allowence(
        &avalanche_provider,
        local_token,
        mayan_swap_layer_address,
        value,
        120,
    )
    .await?;
    println!("Increased allowance: {:?}", tx);

    let tx = mayan_swap_layer
        .bridge(
            value_u64,
            0,
            0,
            bytes_address.try_into()?,
            30,
            bytes_address.try_into()?,
            0,
            1,
            172000,
            1753285701,
            Bytes::from_hex("00")?,
        )
        .send()
        .await?;
    let receipt = tx.watch().await?;
    println!("MayanSwapLayer Bridge Receipt: {:?}", receipt);

    Ok(())
}
