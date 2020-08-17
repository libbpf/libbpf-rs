use std::path::PathBuf;

use anyhow::Result;

use crate::metadata;
use crate::metadata::UnprocessedObj;

fn gen_skel(_debug: bool, _obj: &UnprocessedObj) -> Result<()> {
    Ok(())
}

pub fn gen(debug: bool, manifest_path: Option<&PathBuf>) -> i32 {
    let to_gen = match metadata::get(debug, manifest_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    };

    if debug && !to_gen.is_empty() {
        println!("Found bpf objs to gen skel:");
        for obj in &to_gen {
            println!("\t{:?}", obj);
        }
    } else if to_gen.is_empty() {
        eprintln!("Did not find any bpf objects to generate skeleton");
        return 1;
    }

    for obj in to_gen {
        match gen_skel(debug, &obj) {
            Ok(_) => (),
            Err(e) => {
                eprintln!(
                    "Failed to generate skeleton for {}: {}",
                    obj.path.as_path().display(),
                    e
                );
                return 1;
            }
        }
    }

    0
}
