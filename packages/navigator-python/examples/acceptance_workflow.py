"""Public Navigator workflow: switch local/external only through Deployment."""

import asyncio
import os
from pathlib import Path

from navigator import (
    AcceptanceWorkflow,
    CleanupRequired,
    CursorFile,
    Deployment,
    Identity,
    Operation,
    OperationStatus,
    Session,
    Template,
    TransportUnavailable,
    configured_navigator,
    managed_template,
    new_identity,
)

_TERMINAL_OPERATION_STATUSES = {
    OperationStatus.SUCCEEDED,
    OperationStatus.FAILED,
    OperationStatus.CANCELLED,
}


async def wait_for_terminal_operation(
    workflow: AcceptanceWorkflow, session_id: Identity, operation: Operation
) -> Operation:
    """Do not cross reset until public durable state proves terminal cleanup."""
    async with asyncio.timeout(30):
        current = operation
        while current.status not in _TERMINAL_OPERATION_STATUSES:
            await asyncio.sleep(0.05)
            current = await workflow.navigator.operation(session_id, current.id)
        return current


async def reset_after_reconciliation(
    workflow: AcceptanceWorkflow, session: Session, template: Template
) -> Session:
    """Retry uncertain transport exactly; start a new attempt after cleanup."""
    backoff = 0.05
    async with asyncio.timeout(30):
        while True:
            request_id = new_identity()
            candidate_session_id = new_identity()
            while True:
                try:
                    return await workflow.reset(
                        session,
                        template,
                        "acceptance-example",
                        b"",
                        request_id=request_id,
                        session_id=candidate_session_id,
                    )
                except TransportUnavailable:
                    # The Reset may have committed before its response was
                    # lost. Exact replay is the only safe transport retry.
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 0.5)
                except CleanupRequired:
                    # This is an authoritative outcome, not an uncertain
                    # delivery. A later attempt receives fresh identities.
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 0.5)
                    break


def deployment_from_environment() -> Deployment:
    mode = os.environ.get("NAVIGATOR_MODE", "external")
    if mode == "external":
        return Deployment(mode="external", endpoint=os.environ["NAVIGATOR_ENDPOINT"],
                          credential=os.environ["NAVIGATOR_CREDENTIAL"])
    if mode == "local":
        return Deployment(mode="local", data_dir=Path(os.environ["NAVIGATOR_DATA_DIR"]))
    raise ValueError("NAVIGATOR_MODE must be external or local")


async def run_example(workflow: AcceptanceWorkflow, template: Template) -> None:
    session = await workflow.open(template, "acceptance-example", b"")
    operation = await workflow.run(
        session, session.root_id, b'{"task":"demonstrate the SDK"}'
    )
    await workflow.subscribe(session, lambda event: print(event.type), limit=1)
    try:
        await workflow.cancel(session, session.root_id)
    except TransportUnavailable as error:
        print(f"cancel requires retry/reconciliation: {error}")
    try:
        await workflow.resume(session)
    except CleanupRequired as error:
        print(f"resume requires cleanup: {error}")
    await wait_for_terminal_operation(workflow, session.id, operation)
    await reset_after_reconciliation(workflow, session, template)


async def main() -> None:
    template = managed_template("Complete the supplied task.")
    async with configured_navigator(deployment_from_environment()) as navigator:
        await run_example(AcceptanceWorkflow(navigator, CursorFile(Path("navigator.cursor"))),
                          template)


if __name__ == "__main__":
    asyncio.run(main())
