import type { Segment } from "../api/types";
import { INTEGRITY_LABEL, INTEGRITY_ORDER, integrityCounts, percent, untrustedShare } from "../lib/format";

interface Props {
  segments: readonly Segment[];
}

function describe(segment: Segment): string {
  const origin = segment.sources.length > 0 ? ` from ${segment.sources.join(", ")}` : "";
  return `${INTEGRITY_LABEL[segment.integrity]}${origin}`;
}

export function ContextView({ segments }: Props) {
  const counts = integrityCounts(segments);
  return (
    <section aria-label="Agent context" className="card">
      <h3>Agent context</h3>
      <p className="muted">
        {percent(untrustedShare(segments))} of the context is untrusted. Hover a span to see where
        it came from.
      </p>
      <ul className="legend">
        {INTEGRITY_ORDER.map((level) => (
          <li key={level}>
            <span className={`chip seg-${level.toLowerCase()}`}>{INTEGRITY_LABEL[level]}</span>{" "}
            {counts[level]} chars
          </li>
        ))}
      </ul>
      <pre className="context">
        {segments.map((segment, index) => (
          <span
            key={index}
            className={`seg seg-${segment.integrity.toLowerCase()}`}
            title={describe(segment)}
          >
            {segment.text}
          </span>
        ))}
      </pre>
    </section>
  );
}
