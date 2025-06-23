// Exploration of types to understand the structure
use corepc_types::v29 as json;
use corepc_types::ScriptSig;

fn main() {
    println!("=== ScriptSig Type Information ===");
    
    // ScriptSig structure
    let script_sig = ScriptSig {
        asm: "OP_DUP OP_HASH160 abc123 OP_EQUALVERIFY OP_CHECKSIG".to_string(),
        hex: "76a914abc12388ac".to_string(),
    };
    
    println!("ScriptSig fields:");
    println!("  asm: {}", script_sig.asm);
    println!("  hex: {}", script_sig.hex);
    
    println!("\n=== RawTransactionInput Type Information ===");
    
    // RawTransactionInput structure
    let raw_input = json::RawTransactionInput {
        txid: "abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234".to_string(),
        vout: 1,
        script_sig: script_sig.clone(),
        txin_witness: Some(vec!["witness1".to_string(), "witness2".to_string()]),
        sequence: 0xFFFFFFFF,
    };
    
    println!("RawTransactionInput fields:");
    println!("  txid: {}", raw_input.txid);
    println!("  vout: {}", raw_input.vout);
    println!("  script_sig.asm: {}", raw_input.script_sig.asm);
    println!("  script_sig.hex: {}", raw_input.script_sig.hex);
    println!("  txin_witness: {:?}", raw_input.txin_witness);
    println!("  sequence: {:#x}", raw_input.sequence);
    
    println!("\n=== Type Location Information ===");
    println!("✓ ScriptSig is located at: corepc_types::ScriptSig (root level)");
    println!("✓ RawTransactionInput is located at: corepc_types::v29::RawTransactionInput");
    println!("✓ script_sig field in RawTransactionInput expects type: corepc_types::ScriptSig");
    
    println!("\n=== Usage Example ===");
    println!("```rust");
    println!("use corepc_types::v29 as json;");
    println!("use corepc_types::ScriptSig;");
    println!();
    println!("let script_sig = ScriptSig {{");
    println!("    asm: \"OP_DUP OP_HASH160 abc123 OP_EQUALVERIFY OP_CHECKSIG\".to_string(),");
    println!("    hex: \"76a914abc12388ac\".to_string(),");
    println!("}};");
    println!();
    println!("let raw_input = json::RawTransactionInput {{");
    println!("    txid: \"transaction_id_here\".to_string(),");
    println!("    vout: 0,");
    println!("    script_sig,");
    println!("    txin_witness: None, // or Some(vec![...])");
    println!("    sequence: 0xFFFFFFFF,");
    println!("}};");
    println!("```");
}