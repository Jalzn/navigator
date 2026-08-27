use navigator_conformance::{
    AuthoritySubject, EvidenceOutcome, EvidenceRecord, FencedSnapshot, FencedWriteSubject,
    Observation, OperationCommand, OperationSubject, StaleEpoch, assert_authority_decreases,
    assert_operation_trace, assert_stale_epoch_is_fenced,
};
use navigator_domain::{Authority, Capability, FencingEpoch, OperationState};
use std::{fs, path::PathBuf};

struct IdleMeansSuccess(OperationState);

impl OperationSubject for IdleMeansSuccess {
    fn state(&self) -> OperationState {
        self.0
    }

    fn execute(&mut self, command: OperationCommand) -> Observation {
        if command == OperationCommand::ObserveIdle {
            self.0 = OperationState::Succeeded;
            Observation::State(self.0)
        } else {
            Observation::Rejected
        }
    }
}

struct UnionAuthority;

impl AuthoritySubject for UnionAuthority {
    fn effective(&self, parent: &Authority, ceiling: &Authority) -> Authority {
        Authority::new(parent.capabilities().chain(ceiling.capabilities()).cloned())
    }
}

struct IgnoresFence(FencedSnapshot);

impl FencedWriteSubject for IgnoresFence {
    fn snapshot(&self) -> FencedSnapshot {
        self.0
    }

    fn takeover(&mut self, epoch: FencingEpoch) {
        self.0.epoch = epoch;
    }

    fn write(&mut self, _epoch: FencingEpoch, value: u64) -> Result<(), StaleEpoch> {
        self.0.value = value;
        self.0.revision += 1;
        self.0.events += 1;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("output directory is required")?;
    fs::create_dir_all(&output)?;

    let read = Capability::new("fs.read")?;
    let write = Capability::new("fs.write")?;
    let shell = Capability::new("process.shell")?;
    let parent = Authority::new([read.clone(), write]);
    let ceiling = Authority::new([read, shell]);
    let old = FencingEpoch::new(7)?;
    let current = FencingEpoch::new(8)?;

    let cases = [
        EvidenceRecord {
            invariant: "NAV-OP-005",
            specification: "docs/principles.md#acceptance-is-not-completion",
            subject: "IdleMeansSuccess",
            incorrect_behavior: "idle inferred as success",
            outcome: outcome(&assert_operation_trace(
                &mut IdleMeansSuccess(OperationState::Queued),
                &[OperationCommand::ObserveIdle],
            )),
            seed: None,
        },
        EvidenceRecord {
            invariant: "NAV-AUTH-001",
            specification: "docs/principles.md#authority-only-decreases",
            subject: "UnionAuthority",
            incorrect_behavior: "delegation uses union",
            outcome: outcome(&assert_authority_decreases(
                &UnionAuthority,
                &parent,
                &ceiling,
            )),
            seed: None,
        },
        EvidenceRecord {
            invariant: "NAV-LEASE-001",
            specification: "docs/principles.md#ownership-is-exclusive-and-fenced",
            subject: "IgnoresFence",
            incorrect_behavior: "stale epoch commits a write",
            outcome: outcome(&assert_stale_epoch_is_fenced(
                &mut IgnoresFence(FencedSnapshot {
                    epoch: old,
                    revision: 1,
                    value: 0,
                    events: 0,
                }),
                old,
                current,
            )),
            seed: None,
        },
    ];

    fs::write(
        output.join("semantic-evidence.json"),
        serde_json::to_vec_pretty(&cases)?,
    )?;
    let human = cases
        .iter()
        .map(EvidenceRecord::human)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(output.join("semantic-evidence.txt"), format!("{human}\n"))?;

    if cases
        .iter()
        .all(|case| case.outcome == EvidenceOutcome::MutantRejected)
    {
        Ok(())
    } else {
        Err("one or more semantic mutants survived".into())
    }
}

fn outcome(result: &Result<(), String>) -> EvidenceOutcome {
    if result.is_err() {
        EvidenceOutcome::MutantRejected
    } else {
        EvidenceOutcome::Failed
    }
}
