use std::future::Future;

use navigator_domain::{CanonicalJson, HostId, MAX_TOOL_INLINE_BYTES, ToolResult};
use navigator_store_api::{
    RequestContext, ReserveToolInvocation, StoreError, ToolInvocationPhase, ToolStore,
    ToolTransition, TransitionToolInvocation,
};

/// Backend fixture prepares the Session/ownership/operation/authority and one
/// stable Tool registration. The shared contract owns all replay mutants.
pub trait ToolStoreFixture {
    type Store: ToolStore;
    fn store(&self) -> &Self::Store;
    fn prepare_tool_invocation(
        &mut self,
    ) -> impl Future<
        Output = Result<
            (
                ReserveToolInvocation,
                navigator_store_api::ToolProviderConnectionSnapshot,
            ),
            String,
        >,
    > + Send;
    fn alternate_host(&self) -> HostId;
    fn next_context(&mut self, caller: HostId) -> RequestContext;
    fn reopen(&mut self) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[allow(clippy::too_many_lines)]
pub async fn assert_tool_store_contract<F: ToolStoreFixture>(
    fixture: &mut F,
) -> Result<(), String> {
    let (reserve, connection) = fixture.prepare_tool_invocation().await?;
    let first = fixture
        .store()
        .reserve_tool_invocation(reserve.clone())
        .await
        .map_err(show)?;
    if first.phase() != ToolInvocationPhase::Reserved {
        return Err("Tool was visible only after dispatch".into());
    }
    fixture.reopen().await.map_err(show)?;
    if fixture
        .store()
        .reserve_tool_invocation(reserve.clone())
        .await
        .map_err(show)?
        != first
    {
        return Err("exact Tool reservation did not replay".into());
    }
    let mut caller_mutant = reserve.clone();
    caller_mutant.context =
        RequestContext::new(reserve.context.request_id(), fixture.alternate_host());
    if !matches!(
        fixture.store().reserve_tool_invocation(caller_mutant).await,
        Err(StoreError::RequestConflict { .. })
    ) {
        return Err("Tool replay accepted a different caller".into());
    }
    let start = TransitionToolInvocation {
        context: fixture.next_context(reserve.context.caller()),
        invocation_id: first.invocation().invocation_id(),
        owner_epoch: reserve.owner_epoch,
        expected_revision: first.revision(),
        transition: ToolTransition::Start,
        provider_id: reserve.provider_id,
        connection_id: connection.connection_id,
        connection_generation: connection.generation,
        dispatch_id: reserve.dispatch_id,
        server_sequence: first.dispatch().server_sequence,
    };
    let started = fixture
        .store()
        .transition_tool_invocation(start.clone())
        .await
        .map_err(show)?;
    if started.phase() != ToolInvocationPhase::Started {
        return Err("started acknowledgement did not advance Tool effect".into());
    }
    if fixture
        .store()
        .transition_tool_invocation(start)
        .await
        .map_err(show)?
        != started
    {
        return Err("Tool start did not replay".into());
    }
    let result = ToolResult::new(
        started.invocation().invocation_id(),
        CanonicalJson::<MAX_TOOL_INLINE_BYTES>::new(r#"{"found":true}"#).unwrap(),
        vec![],
    )
    .unwrap();
    let complete = TransitionToolInvocation {
        context: fixture.next_context(reserve.context.caller()),
        invocation_id: started.invocation().invocation_id(),
        owner_epoch: reserve.owner_epoch,
        expected_revision: started.revision(),
        transition: ToolTransition::Complete(result),
        provider_id: reserve.provider_id,
        connection_id: connection.connection_id,
        connection_generation: connection.generation,
        dispatch_id: reserve.dispatch_id,
        server_sequence: started.dispatch().server_sequence,
    };
    let terminal = fixture
        .store()
        .transition_tool_invocation(complete.clone())
        .await
        .map_err(show)?;
    if terminal.phase() != ToolInvocationPhase::Completed {
        return Err("Tool terminal was not durable".into());
    }
    fixture.reopen().await.map_err(show)?;
    if fixture
        .store()
        .transition_tool_invocation(complete)
        .await
        .map_err(show)?
        != terminal
    {
        return Err("Tool terminal did not replay after reopen".into());
    }
    if !fixture
        .store()
        .list_recoverable_tool_invocations(reserve.invocation.session_id())
        .await
        .map_err(show)?
        .is_empty()
    {
        return Err("terminal Tool leaked into recovery inventory".into());
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn show(error: StoreError) -> String {
    error.to_string()
}

/// Recovery after a terminal-Uncertain Tool operation is new work, never a
/// replay of the old effect identity.
pub fn assert_uncertain_tool_replacement_identity(
    old: &navigator_domain::ToolInvocation,
    replacement: &navigator_domain::ToolInvocation,
) -> Result<(), String> {
    if old.session_id() != replacement.session_id()
        || old.participant_id() != replacement.participant_id()
        || old.tool_name() != replacement.tool_name()
        || old.tool_version() != replacement.tool_version()
        || old.operation_id() == replacement.operation_id()
        || old.invocation_id() == replacement.invocation_id()
        || old.request_id() == replacement.request_id()
    {
        return Err("Uncertain Tool replacement did not establish a new causal identity".into());
    }
    Ok(())
}
