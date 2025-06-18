use bdk_sp::send::psbt::derive_sp;
use bdk_sp::{encoding::SilentPaymentCode, receive::scan::Scanner};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable_now, group_by_spk, selection_algorithm_lowest_fee_bnb, ChangePolicyType,
    Output, PsbtParams, SelectorParams, Signer,
};
use bitcoin::{
    key::Secp256k1, secp256k1::SecretKey, Amount, FeeRate, Network, PrivateKey, Sequence,
    Transaction, TxOut,
};
use miniscript::Descriptor;

use std::collections::BTreeMap;

mod common;

use common::Wallet;

const SILENT_PAYMENT_SPEND_PRIVKEY: &str = "cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11";
const SILENT_PAYMENT_SCAN_PRIVKEY: &str = "cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24";
const SILENT_PAYMENT_ENCODED: &str = "sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz";

fn assert_silentpayment_derivation(tx: &Transaction, prevouts: &[TxOut]) {
    let secp = Secp256k1::new();
    let (sp_code, scan_sk, spend_sk) = get_silentpayment_keys();

    let scanner = Scanner::new(scan_sk, sp_code.spend, <BTreeMap<_, _>>::new());

    let found_spouts = scanner.scan_tx(tx, prevouts).expect("should find spouts");

    assert!(!found_spouts.is_empty());

    for sp_output in found_spouts {
        let output_sk = spend_sk.add_tweak(&sp_output.tweak.into()).unwrap();
        // Check the output is spendable
        assert_eq!(output_sk.x_only_public_key(&secp).0, sp_output.xonly_pubkey);
    }
}

pub fn get_silentpayment_keys() -> (SilentPaymentCode, SecretKey, SecretKey) {
    let secp = Secp256k1::new();
    let spend_privkey = SecretKey::from_slice(
        &PrivateKey::from_wif(SILENT_PAYMENT_SPEND_PRIVKEY)
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let scan_privkey = SecretKey::from_slice(
        &PrivateKey::from_wif(SILENT_PAYMENT_SCAN_PRIVKEY)
            .unwrap()
            .to_bytes(),
    )
    .unwrap();

    let sp_code = SilentPaymentCode {
        version: 0,
        scan: scan_privkey.public_key(&secp),
        spend: spend_privkey.public_key(&secp),
        network: Network::Regtest,
    };

    assert_eq!(format!("{}", sp_code), SILENT_PAYMENT_ENCODED);

    (sp_code, scan_privkey, spend_privkey)
}

fn main() -> anyhow::Result<()> {
    let secp = Secp256k1::new();
    let (external, external_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[3])?;
    let (internal, internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[4])?;

    let signer = Signer(external_keymap.into_iter().chain(internal_keymap).collect());

    let env = TestEnv::new()?;
    let genesis_hash = env.genesis_hash()?;
    env.mine_blocks(101, None)?;

    let mut wallet = Wallet::new(genesis_hash, external, internal.clone())?;
    wallet.sync(&env)?;

    let addr = wallet.next_address().expect("must derive address");

    let txid = env.send(&addr, Amount::ONE_BTC)?;
    env.mine_blocks(1, None)?;
    wallet.sync(&env)?;
    println!("Received {}", txid);
    println!("Balance (confirmed): {}", wallet.balance());

    let txid = env.send(&addr, Amount::ONE_BTC)?;
    wallet.sync(&env)?;
    println!("Received {txid}");
    println!("Balance (pending): {}", wallet.balance());

    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;
    let longterm_feerate = FeeRate::from_sat_per_vb_unchecked(1);

    let (sp_code, ..) = get_silentpayment_keys();
    let recipients = vec![sp_code.clone()];
    let recipient_placeholder = sp_code.get_placeholder_p2tr_spk()?;

    // Okay now create tx.
    let selection = wallet
        .all_candidates()
        .regroup(group_by_spk())
        .filter(filter_unspendable_now(tip_height, tip_time))
        .into_selection(
            selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
            SelectorParams::new(
                FeeRate::from_sat_per_vb_unchecked(10),
                vec![Output::with_script(
                    recipient_placeholder.clone(),
                    Amount::from_sat(21_000_000),
                )],
                internal.at_derivation_index(0)?,
                bdk_tx::ChangePolicyType::NoDustAndLeastWaste { longterm_feerate },
            ),
        )?;

    let mut psbt = selection.create_psbt(PsbtParams {
        fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    })?;

    let finalizer = selection.clone().into_finalizer();

    let _ = psbt.sign(&signer, &secp);
    // Finalization is key for sp derivation as the witness provides the knowledge of the type of
    // key used for signing, allowing to know which keys to select for intermediate secret
    // derivation
    let res = finalizer.finalize(&mut psbt);
    assert!(res.is_finalized());

    for (plan_input, psbt_input) in selection.inputs.iter().zip(psbt.inputs.iter_mut()) {
        if let Some(plan) = plan_input.plan() {
            // add bip32 and tap key derivation data
            plan.update_psbt_input(psbt_input);
        }
    }

    // replace outputs by real final silentpayment script pubkeys
    derive_sp(&mut psbt, &signer, &recipients, &secp)?;

    // Prepare for resign
    for psbt_input in psbt.inputs.iter_mut() {
        psbt_input.final_script_sig = None;
        psbt_input.final_script_witness = None;
    }

    // sign again
    let _ = psbt.sign(&signer, &secp);
    let res = finalizer.finalize(&mut psbt);
    assert!(res.is_finalized());

    let tx = psbt.extract_tx()?;
    assert_eq!(tx.input.len(), 2);
    let fee = wallet.graph.graph().calculate_fee(&tx)?;
    println!(
        "ORIGINAL TX: inputs={}, outputs={}, fee={}, feerate={}",
        tx.input.len(),
        tx.output.len(),
        fee,
        ((fee.to_sat() as f32) / (tx.weight().to_vbytes_ceil() as f32)),
    );

    // We will try bump this tx fee.
    let txid = env.rpc_client().send_raw_transaction(&tx)?;
    println!("tx broadcasted: {}", txid);
    wallet.sync(&env)?;
    println!("Balance (send tx): {}", wallet.balance());

    // Try cancel a tx.
    // We follow all the rules as specified by
    // https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md#current-replace-by-fee-policy
    println!("OKAY LET's TRY CANCEL {}", txid);
    {
        let original_tx = wallet
            .graph
            .graph()
            .get_tx_node(txid)
            .expect("must find tx");
        assert_eq!(txid, original_tx.txid);

        // We canonicalize first.
        //
        // This ensures all input candidates are of a consistent UTXO set.
        // The canonicalization is modified by excluding the original txs and their
        // descendants. This way, the prevouts of the original txs are avaliable for spending
        // and we won't end up picking outputs of the original txs.
        //
        // Additionally, we need to guarantee atleast one prevout of each original tx is picked,
        // otherwise we may not actually replace the original txs. The policy used here is to
        // choose the largest value prevout of each original tx.
        //
        // Filters out unconfirmed input candidates unless it was already an input of an
        // original tx we are replacing (as mentioned in rule 2 of Bitcoin Core Mempool
        // Replacement Policy).
        let (rbf_candidates, rbf_params) = wallet.rbf_candidates([txid], tip_height)?;

        let selection = rbf_candidates
            // Do coin selection.
            .into_selection(
                // Coin selection algorithm.
                selection_algorithm_lowest_fee_bnb(longterm_feerate, 100_000),
                SelectorParams {
                    // This is just a lower-bound feerate. The actual result will be much higher to
                    // satisfy mempool-replacement policy.
                    target_feerate: FeeRate::from_sat_per_vb_unchecked(1),
                    // We cancel the tx by specifying no target outputs. This way, all excess returns
                    // to our change output (unless if the prevouts picked are so small that it will
                    // be less wasteful to have no output, however that will not be a valid tx).
                    // If you only want to fee bump, put the original txs' recipients here.
                    target_outputs: vec![Output::with_script(
                        recipient_placeholder,
                        Amount::from_sat(21_000_000),
                    )],
                    change_descriptor: internal.at_derivation_index(1)?,
                    change_policy: ChangePolicyType::NoDustAndLeastWaste { longterm_feerate },
                    // This ensures that we satisfy mempool-replacement policy rules 4 and 6.
                    replace: Some(rbf_params),
                },
            )?;

        let mut psbt = selection.create_psbt(PsbtParams {
            // Not strictly necessary, but it may help us replace the tx faster.
            fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        })?;
        println!(
            "selected inputs: {:?}",
            selection
                .inputs
                .iter()
                .map(|input| input.prev_outpoint())
                .collect::<Vec<_>>()
        );

        let finalizer = selection.clone().into_finalizer();
        psbt.sign(&signer, &secp).expect("failed to sign");

        assert!(
            finalizer.finalize(&mut psbt).is_finalized(),
            "must finalize"
        );

        for (plan_input, psbt_input) in selection.inputs.iter().zip(psbt.inputs.iter_mut()) {
            if let Some(plan) = plan_input.plan() {
                // add bip32 and tap key derivation data
                plan.update_psbt_input(psbt_input);
            }
        }

        // replace outputs by real final silentpayment script pubkeys
        derive_sp(&mut psbt, &signer, &recipients, &secp)?;

        // Prepare for resign
        for psbt_input in psbt.inputs.iter_mut() {
            psbt_input.final_script_sig = None;
            psbt_input.final_script_witness = None;
        }

        // sign again
        let _ = psbt.sign(&signer, &secp);
        let res = finalizer.finalize(&mut psbt);
        assert!(res.is_finalized());

        let tx = psbt.clone().extract_tx()?;
        let fee = wallet.graph.graph().calculate_fee(&tx)?;
        println!(
            "REPLACEMENT TX: inputs={}, outputs={}, fee={}, feerate={}",
            tx.input.len(),
            tx.output.len(),
            fee,
            ((fee.to_sat() as f32) / (tx.weight().to_vbytes_ceil() as f32)),
        );
        let txid = env.rpc_client().send_raw_transaction(&tx)?;
        println!("tx broadcasted: {}", txid);
        wallet.sync(&env)?;
        println!("Balance (RBF): {}", wallet.balance());
        let block_hashes = env.mine_blocks(1, None)?;
        let sp_block_hash = block_hashes.first().unwrap();

        let tx_to_scan = env
            .rpc_client()
            .get_raw_transaction(&txid, Some(sp_block_hash))
            .unwrap();

        let prevouts = psbt
            .inputs
            .into_iter()
            .map(|x| x.witness_utxo.unwrap())
            .collect::<Vec<TxOut>>();
        assert_silentpayment_derivation(&tx_to_scan, &prevouts);
    }

    Ok(())
}
