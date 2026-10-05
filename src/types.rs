use serde::{Deserialize, Serialize};

pub const SPEC_VERSION: &str = "0.1";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PRODUCER_NAME: &str = "closeout-reference";
pub const PUBLIC_POLICY_PATH: &str = ".agents/closeout.yaml";
pub const OUTPUT_CAP_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Gate {
    #[serde(rename = "beforePR")]
    BeforePr,
}

impl Gate {
    pub fn as_str(self) -> &'static str {
        "beforePR"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    P0,
    P1,
    P2,
    P3,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Self::P0 => 0,
            Self::P1 => 1,
            Self::P2 => 2,
            Self::P3 => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::P0 => "P0",
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Independence {
    #[serde(rename = "differentSession")]
    pub different_session: bool,
    #[serde(rename = "differentModel")]
    pub different_model: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub id: String,
    pub gate: Gate,
    pub paths: Vec<String>,
    pub body: ItemBody,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemBody {
    Command {
        exec: Vec<String>,
        timeout_seconds: u64,
    },
    Review {
        skill: String,
        independence: Independence,
        fail_on: Severity,
    },
    Unsupported {
        kind: String,
    },
    Setup {
        exec: Vec<String>,
        timeout_seconds: u64,
    },
}

impl Item {
    pub fn command(id: impl Into<String>, exec: Vec<String>, timeout_seconds: u64) -> Self {
        Self {
            id: id.into(),
            gate: Gate::BeforePr,
            paths: Vec::new(),
            body: ItemBody::Command { exec, timeout_seconds },
        }
    }

    pub fn review(id: impl Into<String>, skill: impl Into<String>, independence: Independence, fail_on: Severity) -> Self {
        Self {
            id: id.into(),
            gate: Gate::BeforePr,
            paths: Vec::new(),
            body: ItemBody::Review {
                skill: skill.into(),
                independence,
                fail_on,
            },
        }
    }

    pub fn unsupported(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            gate: Gate::BeforePr,
            paths: Vec::new(),
            body: ItemBody::Unsupported { kind: kind.into() },
        }
    }

    pub fn setup(id: impl Into<String>, exec: Vec<String>, timeout_seconds: u64) -> Self {
        Self {
            id: id.into(),
            gate: Gate::BeforePr,
            paths: Vec::new(),
            body: ItemBody::Setup { exec, timeout_seconds },
        }
    }

    pub fn with_paths(mut self, paths: Vec<String>) -> Self {
        self.paths = paths;
        self
    }

    pub fn kind_name(&self) -> &str {
        match &self.body {
            ItemBody::Command { .. } => "command",
            ItemBody::Review { .. } => "review",
            ItemBody::Setup { .. } => "setup",
            ItemBody::Unsupported { kind } => kind,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub absent: bool,
    pub path: Option<String>,
    pub digest: Option<String>,
    pub files: Vec<PolicyFile>,
    pub setup: Vec<Item>,
    pub items: Vec<Item>,
    pub warnings: Vec<Warning>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadResult {
    Ready(ResolvedPolicy),
    Failed {
        code: &'static str,
        message: String,
        warnings: Vec<Warning>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub session: String,
    pub model: String,
    pub provider: String,
}

impl Default for Candidate {
    fn default() -> Self {
        Self {
            session: String::new(),
            model: String::new(),
            provider: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub location: String,
    pub explanation: String,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecInfo {
    pub argv: Vec<String>,
    #[serde(rename = "exitCode")]
    pub exit_code: Option<i32>,
    #[serde(rename = "timedOut")]
    pub timed_out: bool,
    pub dirty: bool,
    #[serde(rename = "headMoved")]
    pub head_moved: bool,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRecord {
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "itemId")]
    pub item_id: String,
    pub base: String,
    pub head: String,
    #[serde(rename = "policyDigest")]
    pub policy_digest: String,
    pub attempt: u64,
    pub evaluator: ProducerIdentity,
    pub producer: ProducerIdentity,
    pub exec: ExecInfo,
    pub artifacts: Vec<Artifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewProducer {
    pub session: String,
    pub model: String,
    pub provider: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRecord {
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "itemId")]
    pub item_id: String,
    pub base: String,
    pub head: String,
    #[serde(rename = "policyDigest")]
    pub policy_digest: String,
    pub attempt: u64,
    pub evaluator: ProducerIdentity,
    pub producer: ReviewProducer,
    pub findings: Vec<Finding>,
    pub artifacts: Vec<Artifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "recordType")]
pub enum EvidenceRecord {
    #[serde(rename = "command")]
    Command(CommandRecord),
    #[serde(rename = "review")]
    Review(ReviewRecord),
}

impl EvidenceRecord {
    pub fn item_id(&self) -> &str {
        match self {
            Self::Command(record) => &record.item_id,
            Self::Review(record) => &record.item_id,
        }
    }

    pub fn base(&self) -> &str {
        match self {
            Self::Command(record) => &record.base,
            Self::Review(record) => &record.base,
        }
    }

    pub fn head(&self) -> &str {
        match self {
            Self::Command(record) => &record.head,
            Self::Review(record) => &record.head,
        }
    }

    pub fn policy_digest(&self) -> &str {
        match self {
            Self::Command(record) => &record.policy_digest,
            Self::Review(record) => &record.policy_digest,
        }
    }

    pub fn attempt(&self) -> u64 {
        match self {
            Self::Command(record) => record.attempt,
            Self::Review(record) => record.attempt,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemState {
    Passed,
    Failed,
    Missing,
    Stale,
    Unsupported,
    Independence,
    Untrusted,
    Invalid,
    Skipped,
}

impl ItemState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::Unsupported => "unsupported",
            Self::Independence => "independence",
            Self::Untrusted => "untrusted",
            Self::Invalid => "invalid",
            Self::Skipped => "skipped",
        }
    }

    pub fn blocks(self) -> bool {
        matches!(
            self,
            Self::Missing | Self::Stale | Self::Unsupported | Self::Independence | Self::Untrusted | Self::Invalid
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemResult {
    pub id: String,
    pub kind: String,
    pub state: ItemState,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionName {
    Accepted,
    Rejected,
    Blocked,
}

impl DecisionName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub path: Option<String>,
    pub digest: Option<String>,
    pub absent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    pub decision: DecisionName,
    pub gate: Gate,
    pub base: String,
    pub head: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub candidate: Candidate,
    pub policy: PolicyInfo,
    pub items: Vec<ItemResult>,
    pub warnings: Vec<Warning>,
}
