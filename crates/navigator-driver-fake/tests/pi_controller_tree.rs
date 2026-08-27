#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use navigator_domain::{
    AuthorityCeilings, AuthorityProfile, BoundedBytes, BoundedText, Capability,
    CompatibilityIdentity, ConsumerKey, DriverCapabilityRequirement, DriverId, DriverRequirement,
    Grant, GrantId, HostId, InputSchema, LaunchAttemptId, MessageBody, MessageId, OperationId,
    OperationState, ParticipantId, PublicOperationOutcome, RequestId, ResourceBounds,
    ResourceScope, ScopedCapability, SemanticDigest, SessionCompatibilityManifest, SessionId,
    Template, TemplateCompatibilityBinding, TemplateId, Timestamp, TrustedConfiguration,
};
use navigator_driver_protocol::v1;
use navigator_local::{ConfiguredRuntimeComponents, LocalNavigator, TrustedDriverCatalog};
use navigator_store_api::{
    AuthorityPolicySnapshot, AuthorityStore, AuthorityTemplatePolicy, CreateRootParticipant,
    EventReadLimit, InstanceStore, IssueGrant, LeaseDuration, MAX_OPERATION_OUTCOME_BYTES,
    MailboxStore, MessageDeliveryState, OpenSession, OperationStore, OperationTerminalOutcome,
    PutAuthorityPolicy, ReadEvents, RecoveryStore, RegisterAuthorityTemplatePolicy, RequestContext,
    SessionStore, StartOperation,
};
use navigator_store_sqlite::SqliteStore;
use navigator_supervisor::ProcessBackend;
use prost::Message;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::Mutex;
use uuid::Uuid;

mod common;

static PI_TREE_TEST_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Default)]
struct ShutdownRecorder(StdMutex<Vec<(u32, Vec<navigator_local::ShutdownAttemptEvidence>)>>);

impl navigator_local::ShutdownObserver for ShutdownRecorder {
    fn level_completed(&self, depth: u32, attempts: &[navigator_local::ShutdownAttemptEvidence]) {
        self.0.lock().unwrap().push((depth, attempts.to_vec()));
    }
}

fn id<T>(
    value: u128,
    make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> T {
    make(Uuid::from_u128(value)).unwrap()
}
fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
fn package() -> PathBuf {
    common::pi_package::built(&workspace())
}
fn digest(path: &Path) -> String {
    Sha256::digest(fs::read(path).unwrap())
        .iter()
        .fold(String::new(), |mut output, byte| {
            use std::fmt::Write as _;
            write!(output, "{byte:02x}").unwrap();
            output
        })
}

fn decode_base64(value: &str) -> Vec<u8> {
    let mut output = Vec::new();
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes().take_while(|byte| *byte != b'=') {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("noncanonical hierarchy semantic base64"),
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(u8::try_from((accumulator >> bits) & 0xff).unwrap());
            accumulator &= (1_u32 << bits) - 1;
        }
    }
    output
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = chunk
            .iter()
            .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte))
            << (8 * (3 - chunk.len()));
        for index in 0..4 {
            if index <= chunk.len() {
                output.push(char::from(
                    TABLE[((value >> (18 - index * 6)) & 63) as usize],
                ));
            } else {
                output.push('=');
            }
        }
    }
    output
}

fn assert_spawn_semantics(
    command: &str,
    result: &str,
    expected: (
        RequestId,
        TemplateId,
        Option<GrantId>,
        ParticipantId,
        ParticipantId,
        OperationId,
    ),
) {
    let (request, template, grant, parent, child_id, operation_id) = expected;
    let event = v1::DriverEvent::decode(decode_base64(command).as_slice()).unwrap();
    let hierarchy = match event.event.unwrap() {
        v1::driver_event::Event::HierarchyCommand(command) => command,
        other => panic!("expected hierarchy command, got {other:?}"),
    };
    assert_eq!(hierarchy.request_id, request.as_uuid().as_bytes());
    let spawn = match hierarchy.command.unwrap() {
        v1::hierarchy_command::Command::SpawnChild(spawn) => spawn,
        other => panic!("expected spawn command, got {other:?}"),
    };
    assert_eq!(spawn.template_id, template.as_uuid().as_bytes());
    assert_eq!(spawn.task_input, b"{}");
    assert_eq!(
        spawn.grant_id,
        grant.map_or_else(Vec::new, |id| id.as_uuid().as_bytes().to_vec())
    );

    let result = v1::HierarchyResultRequest::decode(decode_base64(result).as_slice()).unwrap();
    assert_eq!(result.hierarchy_request_id, request.as_uuid().as_bytes());
    assert_eq!(
        result.instance.unwrap().participant_id,
        parent.as_uuid().as_bytes()
    );
    let spawned = match result.result.unwrap() {
        v1::hierarchy_result_request::Result::Spawned(spawned) => spawned,
        other => panic!("expected spawned result, got {other:?}"),
    };
    assert_eq!(spawned.participant_id, child_id.as_uuid().as_bytes());
    assert_eq!(spawned.operation_id, operation_id.as_uuid().as_bytes());
    assert_eq!(
        spawned.input_message_id,
        input_message(request).as_uuid().as_bytes()
    );
}
fn runtime_files(root: &Path) -> Vec<(PathBuf, String)> {
    fn visit(root: &Path, output: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, output);
            } else if path.to_string_lossy().contains("navigator-inbox")
                || path.extension().is_some_and(|value| value == "jsonl")
            {
                if let Ok(bytes) = fs::read(&path) {
                    output.push((
                        path,
                        String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]).into_owned(),
                    ));
                }
            }
        }
    }
    let mut output = Vec::new();
    visit(root, &mut output);
    output
}

struct ProcessCleanupGuard {
    root: PathBuf,
}

impl ProcessCleanupGuard {
    fn owners(&self) -> Vec<(u32, String)> {
        runtime_files(&self.root)
            .into_iter()
            .filter(|(path, _)| path.file_name().is_some_and(|name| name == "owner"))
            .filter_map(|(_, body)| {
                serde_json::from_str::<serde_json::Value>(&body)
                    .ok()?
                    .as_object()
                    .and_then(|owner| {
                        Some((
                            owner.get("pid")?.as_u64()?.try_into().ok()?,
                            owner.get("start")?.as_str()?.to_owned(),
                        ))
                    })
            })
            .collect()
    }

    fn live_owner_pids(&self) -> Vec<u32> {
        self.owners()
            .into_iter()
            .filter(|(pid, start)| Self::process_start(*pid).as_ref() == Some(start))
            .map(|(pid, _)| pid)
            .collect()
    }

    fn process_start(pid: u32) -> Option<String> {
        Command::new("ps")
            .args(["-o", "lstart=", "-p", &pid.to_string()])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|output| output.trim().to_owned())
            .filter(|output| !output.is_empty())
    }

    fn process_group(pid: u32, expected_start: &str) -> Option<u32> {
        let observed_start = Self::process_start(pid)?;
        let artifact = package().join("dist/main.js");
        let marker = artifact.to_string_lossy();
        Command::new("ps")
            .args(["-o", "pgid=,command=", "-p", &pid.to_string()])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|output| {
                let line = output.lines().next()?;
                let group = line.split_whitespace().next()?.parse::<u32>().ok()?;
                process_identity_matches(
                    pid,
                    expected_start,
                    &observed_start,
                    group,
                    line,
                    marker.as_ref(),
                )
                .then_some(group)
            })
    }

    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn test_process_groups(&self) -> BTreeSet<u32> {
        self.owners()
            .into_iter()
            .filter_map(|(pid, start)| Self::process_group(pid, &start))
            .collect()
    }
}

fn process_identity_matches(
    pid: u32,
    expected_start: &str,
    observed_start: &str,
    process_group: u32,
    command: &str,
    artifact: &str,
) -> bool {
    expected_start == observed_start && process_group == pid && command.contains(artifact)
}

impl Drop for ProcessCleanupGuard {
    fn drop(&mut self) {
        for pgid in self.test_process_groups() {
            let _ = Command::new("kill")
                .args(["-TERM", &format!("-{pgid}")])
                .status();
            let _ = Command::new("kill")
                .args(["-KILL", &format!("-{pgid}")])
                .status();
        }
    }
}
fn derived<T>(
    domain: &[u8],
    request: RequestId,
    make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> T {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(request.as_uuid().as_bytes());
    let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    make(Uuid::from_bytes(bytes)).unwrap()
}
fn child(request: RequestId) -> ParticipantId {
    derived(
        b"navigator.hierarchy.child.v1",
        request,
        ParticipantId::from_uuid,
    )
}
fn operation(request: RequestId) -> OperationId {
    derived(
        b"navigator.hierarchy.operation.v1",
        request,
        OperationId::from_uuid,
    )
}
fn input_message(request: RequestId) -> MessageId {
    let mut hash = Sha256::new();
    hash.update(b"navigator.hierarchy.message.v1");
    hash.update(request.as_uuid().as_bytes());
    let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    MessageId::from_uuid(Uuid::from_bytes(bytes)).unwrap()
}
fn pi_template(
    template_id: TemplateId,
    driver: DriverId,
    role: &str,
    interactive: bool,
) -> Template {
    let mut caps = vec![
        DriverCapabilityRequirement::new(Capability::new("durable.acceptance").unwrap(), 1, [])
            .unwrap(),
    ];
    if interactive {
        caps.push(
            DriverCapabilityRequirement::new(
                Capability::new("interactive-terminal.v1").unwrap(),
                1,
                [(
                    BoundedText::new("mode").unwrap(),
                    BoundedText::new("line").unwrap(),
                )],
            )
            .unwrap(),
        );
    }
    Template::register(
        template_id,
        BoundedText::new(role).unwrap(),
        DriverRequirement::new(driver, caps).unwrap(),
        TrustedConfiguration::new(BoundedText::new(role).unwrap(), []).unwrap(),
        ResourceBounds::new(64 * 1024 * 1024, 1000, 1).unwrap(),
        InputSchema::new(vec![]).unwrap(),
    )
    .unwrap()
}

struct ProviderIds {
    campaign_template: TemplateId,
    sibling_campaign_template: TemplateId,
    worker_template: TemplateId,
    sibling_worker_template: TemplateId,
    root_grant: GrantId,
    sibling_grant: GrantId,
    campaign_request: RequestId,
    sibling_campaign_request: RequestId,
    worker_request: RequestId,
    sibling_worker_request: RequestId,
    worker_release: PathBuf,
    sibling_worker_release: PathBuf,
}

fn provider_source(ids: &ProviderIds, delayed_cold_start: bool) -> String {
    let module = workspace()
        .join("packages/navigator-driver-pi/node_modules/@earendil-works/pi-ai/dist/index.js");
    format!(
        r"import {{fauxAssistantMessage,fauxProvider,fauxToolCall}} from 'file://{}';
	{}
	import {{access}} from 'node:fs/promises'; import {{watch}} from 'node:fs'; import {{dirname,basename}} from 'node:path';
const releaseA='{}'; const releaseB='{}'; async function waitForRelease(release){{try{{await access(release);return;}}catch{{}} await new Promise((resolve,reject)=>{{const watcher=watch(dirname(release),(event,name)=>{{if(name===basename(release)){{access(release).then(()=>{{watcher.close();resolve();}},()=>{{}});}}}}); watcher.on('error',reject);}});}}
export function register(runtime){{const f=fauxProvider({{tokensPerSecond:1000}}); const factory=async(context)=>{{const messages=context.messages||[]; const s=JSON.stringify(context); const users=messages.filter(m=>m.role==='user').length;
const outcomes=new Set(); for(const message of messages){{if(message.role!=='user'||!Array.isArray(message.content)) continue; for(const part of message.content){{if(part?.type!=='text') continue; try{{const value=JSON.parse(part.text); if(value?.body?.kind==='operation_outcome'&&value.body.outcome==='succeeded'&&typeof value.body.operation_id==='string') outcomes.add(value.body.operation_id);}}catch{{}}}}}}
if(s.includes('Navigator durably received the report')) return fauxAssistantMessage('reported');
if(s.includes('coordinator')&&users===1) return fauxAssistantMessage('ready');
if(s.includes('coordinator')&&s.includes('launch-tree')&&!s.includes('0000000000000000000000000000006e')) return fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'spawn',request_id:'{}',template_id:'{}',task_input_base64:'e30=',grant_id:'{}'}}),{{stopReason:'toolUse'}});
if(s.includes('coordinator')&&s.includes('launch-sibling')&&!s.includes('00000000000000000000000000000071')) return fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'spawn',request_id:'{}',template_id:'{}',task_input_base64:'e30=',grant_id:'{}'}}),{{stopReason:'toolUse'}});
if(s.includes('coordinator')&&(!outcomes.has('67597459-e31b-47a3-9e7a-552068ea1e85')||!outcomes.has('8426ee6e-d28e-491c-8b72-078f0b0a6bdd'))) return fauxAssistantMessage('waiting-for-campaign-outcomes');
if(s.includes('coordinator')) return fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'report',kind:'succeeded',payload:'parent-result'}}),{{stopReason:'toolUse'}});
if(s.includes('campaign-sibling')&&!outcomes.has('b38fd448-f33c-4589-9045-d9c27adad368')&&!s.includes('00000000000000000000000000000072')) return fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'spawn',request_id:'{}',template_id:'{}',task_input_base64:'e30='}}),{{stopReason:'toolUse'}});
if(s.includes('campaign-sibling')&&!outcomes.has('b38fd448-f33c-4589-9045-d9c27adad368')) return fauxAssistantMessage('waiting-for-sibling-worker-outcome');
if(s.includes('campaign-sibling')) return fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'report',kind:'succeeded',payload:'parent-result'}}),{{stopReason:'toolUse'}});
if(s.includes('campaign')&&!outcomes.has('56b71d89-acfc-49d8-a878-cf1bb2bf23dd')&&!s.includes('0000000000000000000000000000006f')) return fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'spawn',request_id:'{}',template_id:'{}',task_input_base64:'e30='}}),{{stopReason:'toolUse'}});
if(s.includes('campaign')&&!outcomes.has('56b71d89-acfc-49d8-a878-cf1bb2bf23dd')) return fauxAssistantMessage('waiting-for-worker-outcome');
if(s.includes('campaign')) return fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'report',kind:'succeeded',payload:'parent-result'}}),{{stopReason:'toolUse'}});
if(s.includes('worker-primary')) await waitForRelease(releaseA);
if(s.includes('worker-sibling')) await waitForRelease(releaseB);
return fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'report',kind:'succeeded',payload:'worker-result'}}),{{stopReason:'toolUse'}});}}; f.setResponses(Array.from({{length:64}},()=>factory)); runtime.registerNativeProvider(f.provider);}}",
        module.display(),
        if delayed_cold_start {
            "await new Promise(resolve => setTimeout(resolve, 6000));"
        } else {
            ""
        },
        ids.worker_release.display(),
        ids.sibling_worker_release.display(),
        ids.campaign_request.as_uuid().simple(),
        ids.campaign_template.as_uuid().simple(),
        ids.root_grant.as_uuid().simple(),
        ids.sibling_campaign_request.as_uuid().simple(),
        ids.sibling_campaign_template.as_uuid().simple(),
        ids.sibling_grant.as_uuid().simple(),
        ids.sibling_worker_request.as_uuid().simple(),
        ids.sibling_worker_template.as_uuid().simple(),
        ids.worker_request.as_uuid().simple(),
        ids.worker_template.as_uuid().simple()
    )
}

fn catalog(directory: &TempDir, provider: &Path, driver: DriverId) -> TrustedDriverCatalog {
    let node = PathBuf::from(
        String::from_utf8(Command::new("which").arg("node").output().unwrap().stdout)
            .unwrap()
            .trim(),
    )
    .canonicalize()
    .unwrap();
    let main = package().join("dist/main.js").canonicalize().unwrap();
    let base = serde_json::json!({"driver_id":driver.to_string(),"executable":node,"executable_sha256":digest(&node),"arguments":["--preserve-symlinks",main],"working_directory":package(),"environment":{},"protocol_version":1,"ownership_channel":"stdin","capabilities":[{"name":"durable.acceptance","version":1}],"bootstrap_configuration":{"provider":"faux","model":"faux-1","authPath":directory.path().join("auth.json"),"providerModule":provider,"cwd":directory.path(),"tools":[]},"trusted_artifacts":[{"path":main,"sha256":digest(&main)},{"path":provider,"sha256":digest(provider)}]});
    let mut interactive = base.clone();
    interactive["process_io_mode"] = "terminal_pty".into();
    interactive["ownership_channel"] = "dedicated_fd".into();
    interactive["bootstrap_configuration"]["terminalMode"] = "line".into();
    interactive["capabilities"].as_array_mut().unwrap().push(serde_json::json!({"name":"interactive-terminal.v1","version":1,"parameters":{"mode":"line"}}));
    let path = directory.path().join("catalog.json");
    fs::write(
        &path,
        serde_json::to_vec(
            &serde_json::json!({"entries":{"headless":base,"interactive":interactive}}),
        )
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    TrustedDriverCatalog::from_path(Some(&path)).unwrap()
}

#[derive(Clone, Copy)]
struct TreeIds {
    host: HostId,
    session: SessionId,
    root: ParticipantId,
    root_op: OperationId,
    root_msg: MessageId,
    driver: DriverId,
    root_template: TemplateId,
    campaign_template: TemplateId,
    worker_template: TemplateId,
    sibling_campaign_template: TemplateId,
    sibling_worker_template: TemplateId,
    campaign_request: RequestId,
    worker_request: RequestId,
    grant: GrantId,
    sibling_campaign_request: RequestId,
    sibling_worker_request: RequestId,
    sibling_grant: GrantId,
    campaign: ParticipantId,
    worker: ParticipantId,
    sibling_campaign: ParticipantId,
    sibling_worker: ParticipantId,
    campaign_op: OperationId,
    worker_op: OperationId,
    sibling_campaign_op: OperationId,
    sibling_worker_op: OperationId,
}

impl TreeIds {
    fn fixed() -> Self {
        let campaign_request = id(110, RequestId::from_uuid);
        let worker_request = id(111, RequestId::from_uuid);
        let sibling_campaign_request = id(113, RequestId::from_uuid);
        let sibling_worker_request = id(114, RequestId::from_uuid);
        Self {
            host: id(100, HostId::from_uuid),
            session: id(101, SessionId::from_uuid),
            root: id(102, ParticipantId::from_uuid),
            root_op: id(103, OperationId::from_uuid),
            root_msg: id(104, MessageId::from_uuid),
            driver: id(105, DriverId::from_uuid),
            root_template: id(106, TemplateId::from_uuid),
            campaign_template: id(107, TemplateId::from_uuid),
            worker_template: id(108, TemplateId::from_uuid),
            sibling_campaign_template: id(109, TemplateId::from_uuid),
            sibling_worker_template: id(116, TemplateId::from_uuid),
            campaign_request,
            worker_request,
            grant: id(112, GrantId::from_uuid),
            sibling_campaign_request,
            sibling_worker_request,
            sibling_grant: id(115, GrantId::from_uuid),
            campaign: child(campaign_request),
            worker: child(worker_request),
            sibling_campaign: child(sibling_campaign_request),
            sibling_worker: child(sibling_worker_request),
            campaign_op: operation(campaign_request),
            worker_op: operation(worker_request),
            sibling_campaign_op: operation(sibling_campaign_request),
            sibling_worker_op: operation(sibling_worker_request),
        }
    }

    fn operations(self) -> [OperationId; 5] {
        [
            self.root_op,
            self.campaign_op,
            self.worker_op,
            self.sibling_campaign_op,
            self.sibling_worker_op,
        ]
    }

    fn participants_child_first(self) -> [ParticipantId; 5] {
        [
            self.worker,
            self.sibling_worker,
            self.campaign,
            self.sibling_campaign,
            self.root,
        ]
    }
}

struct TreeFixture {
    directory: TempDir,
    _navigator: LocalNavigator<SqliteStore>,
    process_guard: ProcessCleanupGuard,
    store: Arc<SqliteStore>,
    controller: Arc<dyn navigator_local::OperationController>,
    backend: Arc<navigator_supervisor::UnixProcessBackend>,
    ids: TreeIds,
    epoch: navigator_domain::FencingEpoch,
    permit: Option<navigator_core::AdmissionPermit>,
    root_launch: Option<navigator_store_api::LaunchSnapshot>,
    attempt_ids: StdMutex<BTreeMap<ParticipantId, LaunchAttemptId>>,
    root_terminal_output: Arc<Mutex<Vec<u8>>>,
    root_terminal_drain:
        Mutex<Option<tokio::task::JoinHandle<navigator_supervisor::SupervisorError>>>,
    shutdown_recorder: Arc<ShutdownRecorder>,
    worker_release: PathBuf,
    sibling_worker_release: PathBuf,
}

impl TreeFixture {
    async fn new() -> Self {
        Self::new_with_delayed_cold_start(false).await
    }

    async fn new_with_delayed_cold_start(delayed_cold_start: bool) -> Self {
        let directory = private_tree_directory();
        let process_guard = ProcessCleanupGuard::new(directory.path().to_path_buf());
        let ids = TreeIds::fixed();
        let worker_release = directory.path().join("worker-a.release");
        let sibling_worker_release = directory.path().join("worker-b.release");
        let provider = prepare_provider(
            &directory,
            &ids,
            &worker_release,
            &sibling_worker_release,
            delayed_cold_start,
        );
        let store = Arc::new(
            SqliteStore::open(directory.path().join("state.db"))
                .await
                .unwrap(),
        );
        let root_compatibility = register_tree_session(&store, &ids).await;
        let shutdown_recorder = Arc::new(ShutdownRecorder::default());
        let components = build_tree_runtime(
            &directory,
            &provider,
            &store,
            &ids,
            shutdown_recorder.clone(),
        );
        let controller = components.controller.clone();
        let backend = components.process_backend.clone();
        let navigator = LocalNavigator::new(
            store.clone(),
            ids.host,
            LeaseDuration::from_millis(300_000).unwrap(),
        )
        .with_configured_runtime(components)
        .unwrap();
        let (epoch, permit) = navigator_local::RecoveryOwnershipInstaller::acquire_and_install(
            &navigator,
            ids.session,
            id(121, RequestId::from_uuid),
        )
        .await
        .unwrap();
        store
            .create_root_participant(CreateRootParticipant {
                context: RequestContext::new(id(122, RequestId::from_uuid), ids.host),
                session_id: ids.session,
                epoch,
                participant_id: ids.root,
                template_id: ids.root_template,
                expected_compatibility: root_compatibility,
            })
            .await
            .unwrap();
        Self {
            directory,
            _navigator: navigator,
            process_guard,
            store,
            controller,
            backend,
            ids,
            epoch,
            permit: Some(permit),
            root_launch: None,
            attempt_ids: StdMutex::new(BTreeMap::new()),
            root_terminal_output: Arc::new(Mutex::new(Vec::new())),
            root_terminal_drain: Mutex::new(None),
            shutdown_recorder,
            worker_release,
            sibling_worker_release,
        }
    }

    fn authority_profile(&self) -> AuthorityProfile {
        let ids = self.ids;
        let rules = [
            (ids.root, "participant.spawn"),
            (ids.campaign, "participant.spawn"),
            (ids.sibling_campaign, "participant.spawn"),
        ]
        .into_iter()
        .map(|(participant, capability)| {
            ScopedCapability::new(
                Capability::new(capability).unwrap(),
                ResourceScope::Participant(participant),
            )
        })
        .chain(ids.operations().into_iter().flat_map(|operation_id| {
            ["message.outcome", "operation.cancel", "operation.resume"]
                .into_iter()
                .map(move |capability| {
                    ScopedCapability::new(
                        Capability::new(capability).unwrap(),
                        ResourceScope::Operation(operation_id),
                    )
                })
        }))
        .collect::<Vec<_>>();
        AuthorityProfile::new(rules.clone(), rules).unwrap()
    }

    async fn configure_authority(&self) {
        let full = self.authority_profile();
        self.store
            .put_authority_policy(PutAuthorityPolicy {
                context: RequestContext::new(id(123, RequestId::from_uuid), self.ids.host),
                session_id: self.ids.session,
                epoch: self.epoch,
                policy: AuthorityPolicySnapshot {
                    session_id: self.ids.session,
                    participant_id: self.ids.root,
                    session: full.clone(),
                    parent: full.clone(),
                    template: full.clone(),
                    relationship: full.clone(),
                    subject: full.clone(),
                },
            })
            .await
            .unwrap();
        self.register_authority_templates(&full).await;
        self.issue_spawn_grants().await;
        self.verify_authority().await;
    }

    async fn register_authority_templates(&self, full: &AuthorityProfile) {
        let ids = self.ids;
        for (index, template_id) in [
            ids.root_template,
            ids.campaign_template,
            ids.sibling_campaign_template,
            ids.worker_template,
            ids.sibling_worker_template,
        ]
        .into_iter()
        .enumerate()
        {
            self.store
                .register_authority_template_policy(RegisterAuthorityTemplatePolicy {
                    context: RequestContext::new(
                        id(130 + index as u128, RequestId::from_uuid),
                        ids.host,
                    ),
                    session_id: ids.session,
                    epoch: self.epoch,
                    policy: AuthorityTemplatePolicy {
                        template_id,
                        allowed_parent_templates: [
                            ids.root_template,
                            ids.campaign_template,
                            ids.sibling_campaign_template,
                        ]
                        .into_iter()
                        .collect(),
                        template: full.clone(),
                        relationship: full.clone(),
                        subject: full.clone(),
                    },
                })
                .await
                .unwrap();
        }
    }

    async fn issue_spawn_grants(&self) {
        for (index, grant_id) in [self.ids.grant, self.ids.sibling_grant]
            .into_iter()
            .enumerate()
        {
            self.store
                .issue_grant(IssueGrant {
                    context: RequestContext::new(
                        id(140 + index as u128 * 2, RequestId::from_uuid),
                        self.ids.host,
                    ),
                    session_id: self.ids.session,
                    epoch: self.epoch,
                    grant: Grant {
                        id: grant_id,
                        session_id: self.ids.session,
                        subject: self.ids.root,
                        authority: ScopedCapability::new(
                            Capability::new("participant.spawn").unwrap(),
                            ResourceScope::Participant(self.ids.root),
                        ),
                        expires_at: Timestamp::new(
                            time::OffsetDateTime::now_utc().unix_timestamp() + 300,
                            0,
                        )
                        .unwrap(),
                        revoked: false,
                    },
                    single_use: true,
                })
                .await
                .unwrap();
        }
    }

    async fn verify_authority(&self) {
        let policy = self
            .store
            .load_authority_policy(self.ids.root)
            .await
            .unwrap();
        let grant = self.store.load_grant(self.ids.grant).await.unwrap();
        assert_eq!(grant.consumed_at, None);
        let requested = ScopedCapability::new(
            Capability::new("participant.spawn").unwrap(),
            ResourceScope::Participant(self.ids.root),
        );
        AuthorityCeilings {
            session: &policy.session,
            parent: &policy.parent,
            template: &policy.template,
            relationship: &policy.relationship,
            subject: &policy.subject,
        }
        .authorize_effect(
            self.ids.root,
            self.ids.session,
            &requested,
            Some(&grant.grant),
            Timestamp::new(time::OffsetDateTime::now_utc().unix_timestamp(), 0).unwrap(),
        )
        .unwrap();
        self.verify_campaign_ceiling(&policy).await;
    }

    async fn verify_campaign_ceiling(&self, policy: &AuthorityPolicySnapshot) {
        let campaign = self
            .store
            .load_authority_template_policy(self.ids.campaign_template)
            .await
            .unwrap();
        let ceilings = AuthorityCeilings {
            session: &policy.session,
            parent: &policy.subject,
            template: &campaign.template,
            relationship: &campaign.relationship,
            subject: &campaign.subject,
        };
        for scope in campaign.subject.active() {
            ceilings
                .authorize_effect(
                    self.ids.campaign,
                    self.ids.session,
                    scope,
                    None,
                    Timestamp::new(time::OffsetDateTime::now_utc().unix_timestamp(), 0).unwrap(),
                )
                .unwrap();
        }
        for scope in campaign.subject.delegable() {
            ceilings.authorize_child_creation(scope).unwrap();
        }
    }

    async fn start_root(&mut self) {
        let input = pi_template(self.ids.root_template, self.ids.driver, "coordinator", true)
            .validate_input(b"{}")
            .unwrap();
        let start = self.controller.start(
            self.permit.take().unwrap(),
            StartOperation {
                context: RequestContext::new(id(141, RequestId::from_uuid), self.ids.host),
                session_id: self.ids.session,
                epoch: self.epoch,
                operation_id: self.ids.root_op,
                participant_id: self.ids.root,
                input_message_id: self.ids.root_msg,
                input,
            },
        );
        tokio::time::timeout(Duration::from_secs(10), start)
            .await
            .expect("root controller start timed out")
            .expect("root controller start failed");
        self.root_launch = Some(self.wait_launch_ready(self.ids.root).await);
        self.start_root_terminal_drain().await;
        self.wait_running_with_input(self.ids.root_op, self.ids.root_msg)
            .await;
        self.write_root_terminal(b"launch-tree\n").await;
    }

    async fn wait_launch_ready(
        &self,
        participant: ParticipantId,
    ) -> navigator_store_api::LaunchSnapshot {
        // This observes end-to-end scheduling, including capacity queueing for
        // the other real Pi nodes. The Driver's own connect/bootstrap deadline
        // remains independently bounded by the trusted catalog.
        let ready = tokio::time::timeout(Duration::from_secs(150), async {
            loop {
                if let Some(launch) = self.active_launch(participant).await
                    && launch.state == navigator_store_api::LaunchState::Ready
                {
                    break launch;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        if let Ok(launch) = ready {
            self.attempt_ids
                .lock()
                .unwrap()
                .insert(participant, launch.attempt_id);
            launch
        } else {
            let launch = self.active_launch(participant).await;
            let mut operations = Vec::new();
            for operation_id in self.ids.operations() {
                operations.push(self.store.load_operation(operation_id).await);
            }
            let files = runtime_files(self.directory.path());
            let terminal = self.root_terminal_output.lock().await.clone();
            panic!(
                "Driver launch did not become Ready: participant={participant}, launch={launch:?}, operations={operations:?}, runtime_files={files:?}, root_terminal={} ",
                String::from_utf8_lossy(&terminal)
            )
        }
    }

    async fn active_launch(
        &self,
        participant: ParticipantId,
    ) -> Option<navigator_store_api::LaunchSnapshot> {
        let inventory = self
            .store
            .load_recovery_inventory(self.ids.session, self.ids.host, self.epoch)
            .await
            .ok()?;
        {
            let mut observed = self.attempt_ids.lock().unwrap();
            for launch in &inventory.launches {
                observed.insert(launch.participant_id, launch.attempt_id);
            }
        }
        inventory
            .launches
            .into_iter()
            .find(|launch| launch.participant_id == participant)
    }

    fn known_attempt(&self, participant: ParticipantId) -> LaunchAttemptId {
        *self
            .attempt_ids
            .lock()
            .unwrap()
            .get(&participant)
            .unwrap_or_else(|| {
                panic!("participant {participant} launch was observed through the Store")
            })
    }

    async fn wait_running_with_input(&self, operation: OperationId, message: MessageId) {
        let running = tokio::time::timeout(Duration::from_secs(150), async {
            loop {
                let accepted = self
                    .store
                    .load_message(message)
                    .await
                    .is_ok_and(|snapshot| {
                        matches!(snapshot.state, MessageDeliveryState::Accepted { .. })
                    });
                let running = self
                    .store
                    .load_operation(operation)
                    .await
                    .is_ok_and(|snapshot| snapshot.state == OperationState::Running);
                if accepted && running {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        if running.is_err() {
            let operation = self.store.load_operation(operation).await;
            let message = self.store.load_message(message).await;
            let participant = operation
                .as_ref()
                .ok()
                .map(|snapshot| snapshot.participant_id);
            let launch = participant
                .map(|participant| self.store.load_launch(self.known_attempt(participant)));
            let launch = match launch {
                Some(launch) => Some(launch.await),
                None => None,
            };
            let files = runtime_files(self.directory.path());
            let terminal = self.root_terminal_output.lock().await.clone();
            panic!(
                "operation input was not Accepted while Running: operation={operation:?}, message={message:?}, launch={launch:?}, runtime_files={files:?}, root_terminal={}",
                String::from_utf8_lossy(&terminal)
            );
        }
    }

    async fn write_root_terminal(&self, input: &[u8]) {
        let launch = self.root_launch.as_ref().unwrap();
        if let Err(error) = self
            .backend
            .write_terminal(
                launch.attempt_id,
                launch.evidence.as_ref().unwrap(),
                input,
                tokio::time::Instant::now() + Duration::from_secs(3),
            )
            .await
        {
            let inspection = self
                .backend
                .inspect(launch.attempt_id, launch.evidence.as_ref().unwrap())
                .await;
            let current_launch = self.store.load_launch(launch.attempt_id).await;
            let ownership = self.store.read_ownership(self.ids.session).await;
            let events = self
                .store
                .read_events(ReadEvents {
                    session_id: self.ids.session,
                    consumer: ConsumerKey::new("pi-tree").unwrap(),
                    after: None,
                    limit: EventReadLimit::new(256).unwrap(),
                })
                .await;
            let operation = self.store.load_operation(self.ids.root_op).await;
            let mailbox = self.store.load_mailbox(self.ids.root).await;
            let terminal = self.root_terminal_output.lock().await.clone();
            panic!(
                "root terminal write {input:?} failed: {error:?}; inspection={inspection:?}; launch={current_launch:?}; ownership={ownership:?}; operation={operation:?}; mailbox={mailbox:?}; events={events:?}; terminal={} ",
                String::from_utf8_lossy(&terminal)
            );
        }
    }

    async fn start_root_terminal_drain(&self) {
        let launch = self.root_launch.as_ref().unwrap();
        let attempt_id = launch.attempt_id;
        let evidence = launch.evidence.clone().unwrap();
        let backend = Arc::clone(&self.backend);
        let output = Arc::clone(&self.root_terminal_output);
        let drain = tokio::spawn(async move {
            loop {
                match backend
                    .read_terminal(
                        attempt_id,
                        &evidence,
                        4096,
                        tokio::time::Instant::now() + Duration::from_millis(100),
                    )
                    .await
                {
                    Ok(bytes) => {
                        let mut output = output.lock().await;
                        let remaining = 65_536usize.saturating_sub(output.len());
                        output.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                    }
                    Err(navigator_supervisor::SupervisorError::Timeout) => {}
                    Err(error) => break error,
                }
            }
        });
        assert!(
            self.root_terminal_drain
                .lock()
                .await
                .replace(drain)
                .is_none()
        );
    }

    fn assert_shutdown_barriers(&self) {
        let observed = self.shutdown_recorder.0.lock().unwrap();
        assert_eq!(
            observed.iter().map(|(depth, _)| *depth).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
        let expected = [
            (3, vec![self.ids.worker, self.ids.sibling_worker]),
            (2, vec![self.ids.campaign, self.ids.sibling_campaign]),
            (1, vec![self.ids.root]),
        ];
        for ((depth, attempts), (expected_depth, mut participants)) in observed.iter().zip(expected)
        {
            assert_eq!(*depth, expected_depth);
            let mut actual = attempts
                .iter()
                .map(|evidence| {
                    assert_eq!(
                        evidence.attempt_id,
                        self.known_attempt(evidence.participant_id)
                    );
                    assert_eq!(
                        evidence.outcome,
                        navigator_local::ShutdownAttemptOutcome::Stopped,
                        "shutdown failed at depth {depth}: {evidence:?}"
                    );
                    evidence.participant_id
                })
                .collect::<Vec<_>>();
            actual.sort_unstable();
            participants.sort_unstable();
            assert_eq!(actual, participants);
        }
    }

    async fn join_root_terminal_drain(&self) {
        let drain = self.root_terminal_drain.lock().await.take().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), drain)
            .await
            .expect("terminal drain did not observe terminal teardown")
            .expect("terminal drain task panicked");
        assert!(!matches!(
            error,
            navigator_supervisor::SupervisorError::Timeout
        ));
    }

    async fn await_primary_chain_running(&self) {
        self.wait_launch_ready(self.ids.worker).await;
        self.wait_running_with_input(self.ids.worker_op, input_message(self.ids.worker_request))
            .await;
        assert!(
            self.store
                .load_operation(self.ids.campaign_op)
                .await
                .is_ok_and(|operation| !operation.state.is_terminal())
        );
    }

    async fn start_and_await_sibling_chain(&self) {
        self.write_root_terminal(b"launch-sibling\n").await;
        self.wait_launch_ready(self.ids.sibling_worker).await;
        self.wait_running_with_input(
            self.ids.sibling_worker_op,
            input_message(self.ids.sibling_worker_request),
        )
        .await;
        for operation_id in [self.ids.campaign_op, self.ids.sibling_campaign_op] {
            let operation = self.store.load_operation(operation_id).await;
            if !operation
                .as_ref()
                .is_ok_and(|operation| !operation.state.is_terminal())
            {
                let participant = operation.as_ref().ok().map(|value| value.participant_id);
                let launch = match participant {
                    Some(participant) => self
                        .store
                        .load_launch(self.known_attempt(participant))
                        .await
                        .ok(),
                    None => None,
                };
                let inspection = match launch.as_ref() {
                    Some(value) if value.evidence.is_some() => {
                        self.backend
                            .inspect(value.attempt_id, value.evidence.as_ref().unwrap())
                            .await
                    }
                    Some(_) | None => Err(navigator_supervisor::SupervisorError::IdentityMismatch),
                };
                let ownership = self.store.read_ownership(self.ids.session).await;
                let events = self
                    .store
                    .read_events(ReadEvents {
                        session_id: self.ids.session,
                        consumer: ConsumerKey::new("pi-tree").unwrap(),
                        after: None,
                        limit: EventReadLimit::new(256).unwrap(),
                    })
                    .await;
                let terminal = self.root_terminal_output.lock().await.clone();
                panic!(
                    "campaign became terminal before its Worker: operation={operation:?}; launch={launch:?}; inspection={inspection:?}; ownership={ownership:?}; events={events:?}; completed_shutdown_levels={:?}; root_terminal={}",
                    self.shutdown_recorder.0.lock().unwrap(),
                    String::from_utf8_lossy(&terminal),
                );
            }
        }
    }

    async fn complete_primary_in_isolation(&self) {
        fs::write(&self.worker_release, b"release").unwrap();
        let completed = tokio::time::timeout(Duration::from_secs(150), async {
            loop {
                let worker = self.store.load_operation(self.ids.worker_op).await;
                let campaign = self.store.load_operation(self.ids.campaign_op).await;
                let sibling_worker = self.store.load_operation(self.ids.sibling_worker_op).await;
                let sibling_campaign = self
                    .store
                    .load_operation(self.ids.sibling_campaign_op)
                    .await;
                let primary_done = worker
                    .is_ok_and(|value| value.state == OperationState::Succeeded)
                    && campaign.is_ok_and(|value| value.state == OperationState::Succeeded);
                let sibling_waiting = sibling_worker
                    .is_ok_and(|value| value.state == OperationState::Running)
                    && sibling_campaign.is_ok_and(|value| value.state == OperationState::Running);
                let root_waiting = self
                    .store
                    .load_operation(self.ids.root_op)
                    .await
                    .is_ok_and(|value| value.state == OperationState::Running);
                if primary_done && sibling_waiting && root_waiting {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        if completed.is_err() {
            let mut operations = Vec::new();
            for operation_id in self.ids.operations() {
                operations.push((operation_id, self.store.load_operation(operation_id).await));
            }
            let mut mailboxes = Vec::new();
            for participant in self.ids.participants_child_first() {
                mailboxes.push((participant, self.store.load_mailbox(participant).await));
            }
            let mut launches = Vec::new();
            for participant in self.ids.participants_child_first() {
                launches.push((
                    participant,
                    self.store
                        .load_launch(self.known_attempt(participant))
                        .await,
                ));
            }
            let terminal = self.root_terminal_output.lock().await.clone();
            let files = runtime_files(self.directory.path());
            self.shutdown().await;
            panic!(
                "primary chain did not finish while sibling remained Running; operations={operations:?}; mailboxes={mailboxes:?}; launches={launches:?}; runtime_files={files:?}; root_terminal={}",
                String::from_utf8_lossy(&terminal)
            );
        }
    }

    async fn complete_sibling_and_root(&self) {
        fs::write(&self.sibling_worker_release, b"release").unwrap();
        let completed = tokio::time::timeout(Duration::from_secs(150), async {
            loop {
                let mut done = true;
                for operation_id in self.ids.operations() {
                    done &= self
                        .store
                        .load_operation(operation_id)
                        .await
                        .is_ok_and(|snapshot| snapshot.state == OperationState::Succeeded);
                }
                if done {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        if completed.is_err() {
            let mut operations = Vec::new();
            for operation_id in self.ids.operations() {
                operations.push(self.store.load_operation(operation_id).await);
            }
            let mut mailboxes = Vec::new();
            for participant in self.ids.participants_child_first() {
                mailboxes.push((participant, self.store.load_mailbox(participant).await));
            }
            let terminal = self.root_terminal_output.lock().await.clone();
            self.shutdown().await;
            panic!(
                "two isolated Pi chains did not complete; operations={operations:?}; mailboxes={mailboxes:?}; root_terminal={}",
                String::from_utf8_lossy(&terminal)
            );
        }
    }

    async fn shutdown(&self) {
        let result = self
            .controller
            .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(90))
            .await;
        let mut launches = Vec::new();
        if result.is_err() {
            for participant in self.ids.participants_child_first() {
                launches.push((participant, self.active_launch(participant).await));
            }
        }
        assert!(
            result.is_ok(),
            "controller shutdown failed: {result:?}; completed_levels={:?}; launches={launches:?}; runtime_files={:?}",
            self.shutdown_recorder.0.lock().unwrap(),
            runtime_files(self.directory.path()),
        );
        self.join_root_terminal_drain().await;
    }

    async fn shutdown_live_tree(&self) {
        for participant in self.ids.participants_child_first() {
            let state = self.launch_state(participant).await;
            if state != navigator_store_api::LaunchState::Ready {
                let mut operations = Vec::new();
                for operation_id in self.ids.operations() {
                    operations.push((operation_id, self.store.load_operation(operation_id).await));
                }
                let terminal = self.root_terminal_output.lock().await.clone();
                panic!(
                    "participant {participant} was {state:?} before shutdown; operations={operations:?}; runtime_files={:?}; root_terminal={}",
                    runtime_files(self.directory.path()),
                    String::from_utf8_lossy(&terminal),
                );
            }
        }
        let result = self
            .controller
            .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(90))
            .await;
        assert!(
            result.is_ok(),
            "live-tree shutdown failed: {result:?}; completed_levels={:?}",
            self.shutdown_recorder.0.lock().unwrap()
        );
        self.join_root_terminal_drain().await;
    }

    async fn launch_state(&self, participant: ParticipantId) -> navigator_store_api::LaunchState {
        self.store
            .load_launch(self.known_attempt(participant))
            .await
            .unwrap()
            .state
    }

    async fn assert_results_and_shutdown(&self) {
        let root_children = self
            .store
            .load_direct_children(self.ids.root)
            .await
            .unwrap();
        let campaign_children = self
            .store
            .load_direct_children(self.ids.campaign)
            .await
            .unwrap();
        let sibling_children = self
            .store
            .load_direct_children(self.ids.sibling_campaign)
            .await
            .unwrap();
        let root_mailbox = self.store.load_mailbox(self.ids.root).await.unwrap();
        let campaign_mailbox = self.store.load_mailbox(self.ids.campaign).await.unwrap();
        let sibling_mailbox = self
            .store
            .load_mailbox(self.ids.sibling_campaign)
            .await
            .unwrap();
        self.assert_pi_journals();
        self.shutdown().await;
        self.assert_stopped().await;
        assert_eq!(root_children.len(), 2);
        assert!(
            root_children
                .iter()
                .any(|child| child.participant_id == self.ids.campaign)
        );
        assert!(
            root_children
                .iter()
                .any(|child| child.participant_id == self.ids.sibling_campaign)
        );
        assert_eq!(campaign_children[0].participant_id, self.ids.worker);
        assert_eq!(sibling_children[0].participant_id, self.ids.sibling_worker);
        assert_exact_outcome(
            &campaign_mailbox,
            self.ids.worker,
            self.ids.campaign,
            self.ids.worker_op,
            self.ids.campaign_op,
            b"worker-result",
        );
        assert_exact_outcome(
            &sibling_mailbox,
            self.ids.sibling_worker,
            self.ids.sibling_campaign,
            self.ids.sibling_worker_op,
            self.ids.sibling_campaign_op,
            b"worker-result",
        );
        assert_exact_outcome(
            &root_mailbox,
            self.ids.campaign,
            self.ids.root,
            self.ids.campaign_op,
            self.ids.root_op,
            b"parent-result",
        );
        assert_exact_outcome(
            &root_mailbox,
            self.ids.sibling_campaign,
            self.ids.root,
            self.ids.sibling_campaign_op,
            self.ids.root_op,
            b"parent-result",
        );
        assert_eq!(outcome_count(&root_mailbox), 2);
        self.assert_input_identities().await;
    }

    async fn assert_stopped(&self) {
        self.assert_shutdown_barriers();
        for participant in self.ids.participants_child_first() {
            let launch = self
                .store
                .load_launch(self.known_attempt(participant))
                .await
                .unwrap();
            assert_eq!(launch.state, navigator_store_api::LaunchState::Stopped);
        }
        assert!(
            self.process_guard.test_process_groups().is_empty()
                && self.process_guard.live_owner_pids().is_empty(),
            "configured runtime left live Driver owners after shutdown"
        );
    }

    fn assert_pi_journals(&self) {
        let records = runtime_files(self.directory.path())
            .into_iter()
            .filter(|(path, _)| path.to_string_lossy().ends_with(".navigator-inbox"))
            .flat_map(|(path, _)| {
                fs::read_to_string(path)
                    .unwrap()
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(&line)
                    .expect("Pi journal contained malformed JSON")
            })
            .filter(|value| value["kind"] == "hierarchy_result")
            .collect::<Vec<_>>();
        let mut exact_semantics = BTreeSet::new();
        for (request, template, grant, parent, child, operation) in [
            (
                self.ids.campaign_request,
                self.ids.campaign_template,
                Some(self.ids.grant),
                self.ids.root,
                self.ids.campaign,
                self.ids.campaign_op,
            ),
            (
                self.ids.worker_request,
                self.ids.worker_template,
                None,
                self.ids.campaign,
                self.ids.worker,
                self.ids.worker_op,
            ),
            (
                self.ids.sibling_campaign_request,
                self.ids.sibling_campaign_template,
                Some(self.ids.sibling_grant),
                self.ids.root,
                self.ids.sibling_campaign,
                self.ids.sibling_campaign_op,
            ),
            (
                self.ids.sibling_worker_request,
                self.ids.sibling_worker_template,
                None,
                self.ids.sibling_campaign,
                self.ids.sibling_worker,
                self.ids.sibling_worker_op,
            ),
        ] {
            let request_hex = request.as_uuid().simple().to_string();
            let matching = records
                .iter()
                .filter(|value| value["requestId"] == request_hex)
                .collect::<Vec<_>>();
            assert_eq!(
                matching.len(),
                1,
                "missing or duplicate Pi journal result for {request_hex}"
            );
            let command = matching[0]["commandSemantic"].as_str().unwrap();
            let result = matching[0]["resultSemantic"].as_str().unwrap();
            assert_spawn_semantics(
                command,
                result,
                (request, template, grant, parent, child, operation),
            );
            assert!(exact_semantics.insert((command.to_owned(), result.to_owned())));
        }
        assert_eq!(exact_semantics.len(), 4);
    }

    async fn assert_input_identities(&self) {
        for (operation_id, request_id) in [
            (self.ids.campaign_op, self.ids.campaign_request),
            (self.ids.worker_op, self.ids.worker_request),
            (
                self.ids.sibling_campaign_op,
                self.ids.sibling_campaign_request,
            ),
            (self.ids.sibling_worker_op, self.ids.sibling_worker_request),
        ] {
            assert_eq!(
                self.store
                    .load_operation(operation_id)
                    .await
                    .unwrap()
                    .input_message_id,
                input_message(request_id)
            );
        }
    }
}

fn private_tree_directory() -> TempDir {
    let directory = tempfile::Builder::new()
        .prefix("nav-pi-tree-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn prepare_provider(
    directory: &TempDir,
    ids: &TreeIds,
    worker_release: &Path,
    sibling_worker_release: &Path,
    delayed_cold_start: bool,
) -> PathBuf {
    let provider = directory.path().join("provider.mjs");
    fs::write(
        &provider,
        provider_source(
            &ProviderIds {
                campaign_template: ids.campaign_template,
                sibling_campaign_template: ids.sibling_campaign_template,
                worker_template: ids.worker_template,
                sibling_worker_template: ids.sibling_worker_template,
                root_grant: ids.grant,
                sibling_grant: ids.sibling_grant,
                campaign_request: ids.campaign_request,
                sibling_campaign_request: ids.sibling_campaign_request,
                worker_request: ids.worker_request,
                sibling_worker_request: ids.sibling_worker_request,
                worker_release: worker_release.to_owned(),
                sibling_worker_release: sibling_worker_release.to_owned(),
            },
            delayed_cold_start,
        ),
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o600)).unwrap();
    provider
}

async fn register_tree_session(store: &SqliteStore, ids: &TreeIds) -> CompatibilityIdentity {
    let templates = [
        pi_template(ids.root_template, ids.driver, "coordinator", true).registration_snapshot(),
        pi_template(ids.campaign_template, ids.driver, "campaign", false).registration_snapshot(),
        pi_template(
            ids.sibling_campaign_template,
            ids.driver,
            "campaign-sibling",
            false,
        )
        .registration_snapshot(),
        pi_template(ids.worker_template, ids.driver, "worker-primary", false)
            .registration_snapshot(),
        pi_template(
            ids.sibling_worker_template,
            ids.driver,
            "worker-sibling",
            false,
        )
        .registration_snapshot(),
    ];
    for template in &templates {
        store.register_template(template.clone()).await.unwrap();
    }
    let manifest = SessionCompatibilityManifest::new(
        CompatibilityIdentity::digest(b"pi-controller-tree-fixed-configuration-v1"),
        templates
            .iter()
            .map(|template| TemplateCompatibilityBinding {
                template_id: template.identity,
                compatibility: template.compatibility,
            })
            .collect(),
    )
    .unwrap();
    store
        .open_session(OpenSession::with_manifest(
            RequestContext::new(id(120, RequestId::from_uuid), ids.host),
            ids.session,
            ConsumerKey::new("pi-tree").unwrap(),
            manifest,
        ))
        .await
        .unwrap();
    templates[0].compatibility
}

fn build_tree_runtime(
    directory: &TempDir,
    provider: &Path,
    store: &Arc<SqliteStore>,
    ids: &TreeIds,
    shutdown_observer: Arc<dyn navigator_local::ShutdownObserver>,
) -> ConfiguredRuntimeComponents {
    navigator_local::build_catalog_runtime_components_with_settings_and_shutdown_observer(
        store.clone(),
        ids.host,
        catalog(directory, provider, ids.driver),
        BTreeSet::from(["headless".into(), "interactive".into()]),
        directory.path().join("runtime"),
        navigator_local::ConfiguredRuntimeSettings::new(8, Duration::from_secs(300))
            .unwrap()
            .with_delivery_budgets(
                Duration::from_secs(30),
                Duration::from_secs(15),
                Duration::from_secs(180),
            )
            .unwrap(),
        Some(shutdown_observer),
    )
    .unwrap()
}

#[tokio::test]
// Guarantees: NAV-CONTROL-001, NAV-DRIVER-001, NAV-ADAPTER-001
async fn controller_persists_and_runs_real_pi_coordinator_campaign_worker_tree() {
    let _tree_test = PI_TREE_TEST_LOCK.lock().await;
    let started = tokio::time::Instant::now();
    let mut fixture = TreeFixture::new().await;
    fixture.configure_authority().await;
    fixture.start_root().await;
    fixture.wait_launch_ready(fixture.ids.campaign).await;
    fixture
        .wait_running_with_input(
            fixture.ids.campaign_op,
            input_message(fixture.ids.campaign_request),
        )
        .await;
    fixture.start_and_await_sibling_chain().await;
    fixture.complete_primary_in_isolation().await;
    fixture.complete_sibling_and_root().await;
    fixture.assert_results_and_shutdown().await;
    assert!(started.elapsed() < Duration::from_secs(600));
}

#[tokio::test]
// Guarantees: NAV-READINESS-001
async fn trusted_pi_cold_start_longer_than_five_seconds_reaches_ready_and_spawns() {
    let _tree_test = PI_TREE_TEST_LOCK.lock().await;
    let mut fixture = TreeFixture::new_with_delayed_cold_start(true).await;
    fixture.configure_authority().await;

    let started = tokio::time::Instant::now();
    fixture.start_root().await;
    assert!(
        started.elapsed() > Duration::from_secs(5),
        "trusted provider cold start must cross the former five-second bootstrap timeout"
    );
    assert_eq!(
        fixture.root_launch.as_ref().unwrap().state,
        navigator_store_api::LaunchState::Ready
    );

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if fixture
                .store
                .load_participant(fixture.ids.campaign)
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the Ready root Driver must execute and durably commit a real spawn");
    fixture.wait_launch_ready(fixture.ids.campaign).await;
    fixture.shutdown().await;
    let root_attempt = fixture.root_launch.as_ref().unwrap().attempt_id;
    assert_eq!(
        fixture.store.load_launch(root_attempt).await.unwrap().state,
        navigator_store_api::LaunchState::Stopped
    );
    assert!(
        fixture.process_guard.test_process_groups().is_empty()
            && fixture.process_guard.live_owner_pids().is_empty(),
        "delayed cold-start fixture left a live Driver owner"
    );
}

#[test]
fn hierarchy_journal_oracle_rejects_wrong_command_semantics() {
    let ids = TreeIds::fixed();
    let event = v1::DriverEvent {
        event: Some(v1::driver_event::Event::HierarchyCommand(
            v1::HierarchyCommand {
                request_id: ids.campaign_request.as_uuid().as_bytes().to_vec(),
                command: Some(v1::hierarchy_command::Command::SpawnChild(
                    v1::SpawnChildCommand {
                        template_id: ids.worker_template.as_uuid().as_bytes().to_vec(),
                        task_input: b"{}".to_vec(),
                        grant_id: ids.grant.as_uuid().as_bytes().to_vec(),
                    },
                )),
            },
        )),
        ..Default::default()
    };
    let command = encode_base64(&event.encode_to_vec());
    assert!(
        std::panic::catch_unwind(|| {
            assert_spawn_semantics(
                &command,
                "ignored",
                (
                    ids.campaign_request,
                    ids.campaign_template,
                    Some(ids.grant),
                    ids.root,
                    ids.campaign,
                    ids.campaign_op,
                ),
            );
        })
        .is_err()
    );
}

#[tokio::test]
async fn session_shutdown_stops_every_live_pi_tree_process() {
    let _tree_test = PI_TREE_TEST_LOCK.lock().await;
    tokio::time::timeout(Duration::from_secs(600), async {
        let mut fixture = TreeFixture::new().await;
        fixture.configure_authority().await;
        fixture.start_root().await;
        fixture.await_primary_chain_running().await;
        fixture.start_and_await_sibling_chain().await;
        fixture.shutdown_live_tree().await;
        fixture.assert_stopped().await;
    })
    .await
    .expect("shutdown smoke exceeded its global deadline");
}

fn outcome_count(messages: &[navigator_store_api::MessageSnapshot]) -> usize {
    messages
        .iter()
        .filter(|message| {
            matches!(
                message.envelope.body(),
                MessageBody::OperationOutcome { .. }
            )
        })
        .count()
}

fn assert_exact_outcome(
    messages: &[navigator_store_api::MessageSnapshot],
    source: ParticipantId,
    destination: ParticipantId,
    operation: OperationId,
    correlated_operation: OperationId,
    payload: &[u8],
) {
    let matching = messages.iter().filter(|message| matches!(message.envelope.body(), MessageBody::OperationOutcome { operation_id, outcome: PublicOperationOutcome::Succeeded, .. } if *operation_id == operation)).collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one outcome for {operation}"
    );
    let message = matching[0];
    assert_eq!(message.source, source);
    assert_eq!(message.destination, destination);
    assert_eq!(message.correlation.operation_id, Some(correlated_operation));
    assert_eq!(message.correlation.in_reply_to, None);
    assert!(matches!(
        message.state,
        MessageDeliveryState::Accepted { .. }
    ));
    let MessageBody::OperationOutcome { result_digest, .. } = message.envelope.body() else {
        unreachable!()
    };
    assert!(exact_outcome_fields(
        message.source,
        message.destination,
        message.correlation.operation_id,
        message.correlation.in_reply_to,
        matches!(message.state, MessageDeliveryState::Accepted { .. }),
        result_digest,
        source,
        destination,
        correlated_operation,
        &expected_public_outcome_digest(payload),
    ));
}

fn expected_public_outcome_digest(payload: &[u8]) -> [u8; 32] {
    let outcome = OperationTerminalOutcome::Succeeded {
        result: BoundedBytes::<MAX_OPERATION_OUTCOME_BYTES>::new(payload.to_vec()).unwrap(),
    };
    let canonical = serde_json::to_vec(&outcome).unwrap();
    *SemanticDigest::v1(
        &Capability::new("operation.public-outcome.v1").unwrap(),
        &canonical,
    )
    .as_bytes()
}

#[expect(
    clippy::too_many_arguments,
    reason = "oracle spells out every persisted outcome field"
)]
fn exact_outcome_fields(
    source: ParticipantId,
    destination: ParticipantId,
    correlated_operation: Option<OperationId>,
    in_reply_to: Option<MessageId>,
    accepted: bool,
    digest: &[u8; 32],
    expected_source: ParticipantId,
    expected_destination: ParticipantId,
    expected_operation: OperationId,
    expected_digest: &[u8],
) -> bool {
    source == expected_source
        && destination == expected_destination
        && correlated_operation == Some(expected_operation)
        && in_reply_to.is_none()
        && accepted
        && digest.as_slice() == expected_digest
}

#[test]
fn outcome_oracle_rejects_each_mutated_evidence_field() {
    let source = id(201, ParticipantId::from_uuid);
    let destination = id(202, ParticipantId::from_uuid);
    let operation = id(203, OperationId::from_uuid);
    let digest = [7; 32];
    let valid = |actual_source, actual_destination, correlation, reply, accepted, actual_digest| {
        exact_outcome_fields(
            actual_source,
            actual_destination,
            correlation,
            reply,
            accepted,
            actual_digest,
            source,
            destination,
            operation,
            &digest,
        )
    };
    assert!(valid(
        source,
        destination,
        Some(operation),
        None,
        true,
        &digest
    ));
    assert!(!valid(
        destination,
        destination,
        Some(operation),
        None,
        true,
        &digest
    ));
    assert!(!valid(source, source, Some(operation), None, true, &digest));
    assert!(!valid(source, destination, None, None, true, &digest));
    assert!(!valid(
        source,
        destination,
        Some(operation),
        Some(id(204, MessageId::from_uuid)),
        true,
        &digest
    ));
    assert!(!valid(
        source,
        destination,
        Some(operation),
        None,
        false,
        &digest
    ));
    assert!(!valid(
        source,
        destination,
        Some(operation),
        None,
        true,
        &[8; 32]
    ));
}

#[test]
fn succeeded_outcome_fixture_matches_the_canonical_wire_shape() {
    let operation_id = OperationId::from_uuid(Uuid::from_u128(1)).unwrap();
    let envelope = navigator_domain::ValidatedMessageEnvelope::operation_outcome(
        operation_id,
        PublicOperationOutcome::Succeeded,
        [2; 32],
    );
    let value: serde_json::Value = serde_json::from_slice(envelope.as_bytes()).unwrap();
    assert_eq!(value["body"]["kind"], "operation_outcome");
    assert_eq!(value["body"]["operation_id"], operation_id.to_string());
    assert_eq!(value["body"]["outcome"], "succeeded");
}

#[test]
fn cleanup_rejects_reused_pid_foreign_group_and_foreign_command() {
    let valid = |start, group, command| {
        process_identity_matches(41, "start-a", start, group, command, "/pi/dist/main.js")
    };
    assert!(valid("start-a", 41, "node /pi/dist/main.js"));
    assert!(!valid("start-b", 41, "node /pi/dist/main.js"));
    assert!(!valid("start-a", 42, "node /pi/dist/main.js"));
    assert!(!valid("start-a", 41, "node unrelated.js"));
}
