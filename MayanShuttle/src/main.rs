use structopt::StructOpt;
use utils::{
    alloy::{
        hex::FromHex,
        primitives::{address, Address, Bytes, FixedBytes, U256},
        providers::Provider,
        sol,
    },
    circle::{get_circle_message_v1, get_circle_message_v2},
    web3::{get_provider, get_wallet, increase_allowence},
    wormhole::{get_latest_sequence, get_vaa, get_vaa_by_sequence},
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
    MayanShuttle,
    "../assets/MayanShuttle.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IWormhole,
    "../assets/IWormhole.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    TestSwapProtocol,
    "../assets/TestSwapProtocol.json"
);

#[derive(Debug, Clone, StructOpt)]
enum Opt {
    #[structopt(name = "bridge")]
    Bridge,

    #[structopt(name = "swap")]
    Swap,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();

    let (address, wallet) = utils::web3::get_wallet()?;
    println!("Wallet Address: {}", address);
    let mut bytes_address = [0u8; 32];
    bytes_address[12..].copy_from_slice(address.as_slice());

    let avalanche_provider = utils::web3::get_provider(&wallet, "https://avalanche.drpc.org")?;
    let base_provider = utils::web3::get_provider(&wallet, "https://base.llamarpc.com")?;

    println!(
        "Avalanche Latest Block: {:?}\nBase Latest Block: {:?}",
        avalanche_provider.get_block_number().await?,
        base_provider.get_block_number().await?
    );

    let mayan_shuttle_address = address!("0x0e689e83E1337037D9bF3A8691A06BD308c78484");
    let mayan_shuttle = MayanShuttle::new(mayan_shuttle_address, avalanche_provider.clone());
    let local_token = mayan_shuttle.localToken().call().await?._0;
    println!("Local Token: {:?}", local_token);
    println!("MayanShuttle Address: {:?}", mayan_shuttle_address);

    // Minimum eligible value to bridge
    let value_u64 = 100000000;
    let value = U256::from(value_u64);
    let tx = utils::web3::increase_allowence(
        &avalanche_provider,
        local_token,
        mayan_shuttle_address,
        value,
        120,
    )
    .await?;
    println!("Increased allowance: {:?}", tx);

    let matching_engine_address =
        "74e70ed52464f997369bbefd141d8a2d9dd3cd15e1f21b37bce18f45e0e923b2";

    match opt {
        Opt::Bridge => {
            let mut latest_sequence =
                get_latest_sequence(1, matching_engine_address.to_string()).await?;
            println!("Latest Sequence: {:?}", latest_sequence);

            let tx = mayan_shuttle
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
            println!("MayanShuttle Bridge Receipt: {:?}", receipt);

            // Because rate of usage of protocol is low this solution works now
            loop {
                let new_seq = get_latest_sequence(1, matching_engine_address.to_string()).await?;
                if new_seq > latest_sequence {
                    latest_sequence = new_seq;
                    println!("New Sequence: {:?}", latest_sequence);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            let (vaa, tx_hash) =
                get_vaa_by_sequence(1, matching_engine_address.to_string(), latest_sequence, 10)
                    .await?;
            println!("VAA: {:?}", vaa);
            println!("Tx Hash: {:?}", tx_hash);

            let circle_message_v2 = get_circle_message_v2(5, tx_hash, 120).await?;
            println!("Circle Message V2: {:?}", circle_message_v2);
            let mayan_shuttle_address = address!("0x36a79a04fbeec88476c7aa0270137f135dc8361c");
            let mayan_shuttle = MayanShuttle::new(mayan_shuttle_address, base_provider.clone());

            let tx = mayan_shuttle
                .redeem(
                    vaa,
                    circle_message_v2.message.unwrap(),
                    circle_message_v2.attestation.unwrap(),
                )
                .send()
                .await?;
            let receipt = tx.watch().await?;
            println!("MayanShuttle Redeem Receipt: {:?}", receipt);
        }
        Opt::Swap => {
            println!("Wallet Address: {}", address);
        }
    }
    Ok(())
}
