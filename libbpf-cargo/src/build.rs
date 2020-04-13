use std::path::PathBuf;

use cargo_metadata::MetadataCommand;

pub fn build(debug: bool, manifest_path: Option<PathBuf>) -> i32 {
    let mut cmd = MetadataCommand::new();

    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    let metadata = match cmd.exec() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to get cargo metadata: {:?}", e);
            return 1;
        }
    };

    if debug {
        for id in metadata.workspace_members {
            println!("workspace member={:?}", id);
        }
    }

    0
}
