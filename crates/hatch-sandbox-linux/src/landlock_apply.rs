use std::path::Path;

use anyhow::{anyhow, Result};
use hatch_core::CompiledPolicy;
use landlock::{
    Access, AccessFs, BitFlags, PathBeneath, PathFd, RestrictionStatus, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI,
};

pub fn apply(policy: &CompiledPolicy) -> Result<RestrictionStatus> {
    let abi = ABI::V1;
    let mut ruleset: RulesetCreated = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| anyhow!("ruleset handle: {e:?}"))?
        .create()
        .map_err(|e| anyhow!("ruleset create: {e:?}"))?;

    let read_access: BitFlags<AccessFs> = AccessFs::from_read(abi);
    let all_access: BitFlags<AccessFs> = AccessFs::from_all(abi);

    for p in &policy.resolved_paths_read {
        if let Some(rule) = path_rule(p, read_access)? {
            ruleset = ruleset
                .add_rule(rule)
                .map_err(|e| anyhow!("add read rule for {p:?}: {e:?}"))?;
        }
    }
    for p in &policy.resolved_paths_write {
        if let Some(rule) = path_rule(p, all_access)? {
            ruleset = ruleset
                .add_rule(rule)
                .map_err(|e| anyhow!("add write rule for {p:?}: {e:?}"))?;
        }
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| anyhow!("restrict_self: {e:?}"))?;
    match status.ruleset {
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => Ok(status),
        RulesetStatus::NotEnforced => Err(anyhow!("Landlock not enforced; kernel too old")),
    }
}

fn path_rule(path: &Path, access: BitFlags<AccessFs>) -> Result<Option<PathBeneath<PathFd>>> {
    if !path.exists() {
        return Ok(None);
    }
    let fd = PathFd::new(path).map_err(|e| anyhow!("open {path:?}: {e:?}"))?;
    Ok(Some(PathBeneath::new(fd, access)))
}
