# ADR-0015: Thermostat weekly schedule semantics

* Status: accepted
* Date: 2026-09-17
* Specification: `ZCL8 §6.3.2.2.3` (schedule attributes), `§6.3.2.3.2`
  (Set Weekly Schedule), `§6.3.2.3.3` (Get Weekly Schedule),
  `§6.3.2.4.1` (Get Weekly Schedule Response)

## Context

The weekly schedule commands leave three points open.

1. `§6.3.2.3.2.2` says Number of Transitions for Sequence "indicates
   how many individual transitions to expect for this sequence of
   commands" and that larger schedules are sent in several commands,
   while `§6.3.2.3.2.1` says the payload is decoded from the three
   header bytes and `§6.3.2.3.2.8` says each command replaces the named
   days. A count spanning several frames cannot be reconciled with a
   per-frame replacement.
2. Get Weekly Schedule takes a Days To Return bitmap, but the response
   has one Day of Week field and transitions without a day, so days
   with different schedules cannot share a response. `§6.3.2.3.3.3`
   allows INVALID_FIELD when a server cannot handle several days.
3. A Get for heat and cool against a day whose sequence was set with
   one mode has no defined encoding for the missing setpoint.

## Decision

* Number of Transitions for Sequence counts the transitions in the
  frame that carries it; the payload length must match exactly
  (MALFORMED_COMMAND otherwise). Each command replaces the transitions
  of every day in its bitmap, as `§6.3.2.3.2.8` describes; a day with
  more transitions than fit one frame is not supported, and
  `NumberOfDailyTransitions` is capped at 10 so a day always fits.
* Get Weekly Schedule accepts exactly one day; several days are refused
  with INVALID_FIELD. The mode returned is the mode asked for
  restricted to the setpoints the server implements (INVALID_FIELD when
  nothing remains).
* A transition lacking a requested setpoint is reported with the
  temperature non-value 0x8000 (`thermostat::UNKNOWN`); a Set carrying
  0x8000 is refused as INVALID_VALUE because it lies outside the Abs
  limits, so a client cannot write the placeholder back.
* The schedule runs against the endpoint's Time server (ZCL local time,
  epoch 2000-01-01 Saturday); the transition in force is the latest one
  today at or before now, else the last of the nearest earlier day with
  any, and it is applied once (`TemperatureSetpointHold` on suspends
  application). Without a clock the schedule is stored but not run.

## Consequences

* Clients reading a whole week issue one Get per day, which is what
  deployed clients do anyway.
* Sequences with the away bit are stored under a separate day and
  never selected by the clock; an application chooses when to apply
  them.
