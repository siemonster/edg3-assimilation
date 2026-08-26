# edg3-assimilation

Normalises heterogeneous security telemetry into one canonical event before it reaches the Edg3 lakehouse.
Point it at syslog, Suricata EVE or Zeek logs and it emits JSON lines on one schema
(`urn:edg3:assim:canon:v1:7f3c9ab2`), so downstream queries stop caring which sensor produced a record.

Experimental. The schema and the control API move with the component.

## Try it

    go build ./cmd/assimilate
    ./assimilate --config examples/config.yaml --dry-run

## How it works

One adapter per wire format parses a line into a flat record. A YAML field map renames and coerces that
record onto the canonical event. A sink writes the result. Adding a format means adding an adapter and a map,
not touching the pipeline.

## Roadmap

- Kafka sink (the interface is in place; the broker client is not vendored yet)
- Field-map updates pulled from the schema registry instead of disk
- Stateful enrichment across events in one flow
