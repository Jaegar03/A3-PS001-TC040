"""SQL predicates isolating command-center records from operational records.

Older SIMULATED/DEMO_DATA sources keep their existing semantics. The dedicated
source also covers legacy command-center records without a linked execution.
"""

from sqlalchemy import and_, exists, literal, or_, select

from app.models.orm import EventORM
from app.models.simulation import SimulationExecutionORM

COMMAND_CENTER_SOURCE = "cyber-defense-lab"


def command_center_event(event_id):
    if isinstance(event_id, str):
        event_id = literal(event_id)
    return or_(
        exists(select(1).where(SimulationExecutionORM.event_id == event_id)),
        event_id.in_(select(EventORM.event_id).where(EventORM.source == COMMAND_CENTER_SOURCE)),
    )


def visible_event(event_id, actor: str):
    owned = exists(select(1).where(
        SimulationExecutionORM.event_id == event_id,
        SimulationExecutionORM.actor_id == actor,
    ))
    return or_(~command_center_event(event_id), owned)


def operational_event(event_id):
    return ~command_center_event(event_id)


def owned_command_center_event(event_id, actor: str):
    return and_(command_center_event(event_id), visible_event(event_id, actor))
