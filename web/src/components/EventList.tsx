import type { TraceEvent } from "../api/types";
import { EVENT_LABEL, formatArgs } from "../lib/format";

interface Props {
  events: readonly TraceEvent[];
}

export function EventList({ events }: Props) {
  return (
    <section aria-label="Event timeline" className="card">
      <h3>Timeline</h3>
      <ol className="events">
        {events.map((event, index) => (
          <li key={index} className={`event event-${event.kind}`}>
            <span className="step">{event.step}</span>
            <span className="kind">{EVENT_LABEL[event.kind]}</span>
            <span className="tool">{event.tool || "agent"}</span>
            {event.args.length > 0 && <code className="args">{formatArgs(event.args)}</code>}
            {event.detail && <p className="detail">{event.detail}</p>}
          </li>
        ))}
      </ol>
    </section>
  );
}
