use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use nix::fcntl::{Flock, FlockArg};

pub fn built(workspace: &Path) -> PathBuf {
    static BUILD_LEASE: OnceLock<Flock<File>> = OnceLock::new();
    let package = workspace.join("packages/navigator-driver-pi");
    BUILD_LEASE.get_or_init(|| build_and_hold_lock(&package));
    package
}

fn build_and_hold_lock(package: &Path) -> Flock<File> {
    let lock = acquire_build_lock(package);
    assert!(
        Command::new("npm")
            .args(["run", "build"])
            .current_dir(package)
            .status()
            .unwrap()
            .success(),
        "Pi Driver TypeScript build failed"
    );
    lock
}

fn acquire_build_lock(package: &Path) -> Flock<File> {
    let lock_path = package.join(".navigator-test-build.lock");
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .unwrap();
    Flock::lock(lock_file, FlockArg::LockExclusive)
        .unwrap_or_else(|(_, error)| panic!("failed to lock Pi package build: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_lock_file_is_persistent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".navigator-test-build.lock");
        let held = acquire_build_lock(directory.path());
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let (contender, _) = Flock::lock(contender, FlockArg::LockExclusiveNonblock)
            .expect_err("a second process must not enter the shared build section");
        drop(held);
        drop(Flock::lock(contender, FlockArg::LockExclusiveNonblock).unwrap());
        assert!(
            path.exists(),
            "advisory lock release must not unlink the inode"
        );
    }
}
