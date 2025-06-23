// Test file to check ScriptSig availability
use corepc_types::v29 as json;

fn main() {
    // Try to access ScriptSig from v29 module
    let _script_sig_from_v29 = json::ScriptSig {
        asm: "".to_string(),
        hex: "".to_string(),
    };
    
    // Try to access ScriptSig from root module
    let _script_sig_from_root = corepc_types::ScriptSig {
        asm: "".to_string(),
        hex: "".to_string(),
    };
    
    println!("ScriptSig is available!");
}