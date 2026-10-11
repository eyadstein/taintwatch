import { useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import type { FamilyInfo, Page, ScenarioDetail, ScenarioSummary } from "../api/types";
import { truncate } from "../lib/format";
import { familyLabel, totalPages } from "../lib/scenario";
import { ComparePanel } from "./ComparePanel";
import { ScenarioView } from "./ScenarioView";

type Kind = "all" | "attack" | "benign";

const PAGE_SIZE = 25;

interface Props {
  onError: (message: string) => void;
  onChanged: () => void;
}

export function ScenarioBrowser({ onError, onChanged }: Props) {
  const [kind, setKind] = useState<Kind>("all");
  const [family, setFamily] = useState("");
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<Page<ScenarioSummary>>({ total: 0, items: [] });
  const [families, setFamilies] = useState<FamilyInfo[]>([]);
  const [detail, setDetail] = useState<ScenarioDetail | null>(null);

  useEffect(() => {
    let active = true;
    api
      .families()
      .then((items) => {
        if (active) setFamilies(items);
      })
      .catch((error: unknown) => onError(errorMessage(error)));
    return () => {
      active = false;
    };
  }, [onError]);

  useEffect(() => {
    let active = true;
    api
      .scenarios({
        attack: kind === "all" ? undefined : kind === "attack",
        family: family || undefined,
        limit: PAGE_SIZE,
        offset,
      })
      .then((result) => {
        if (active) setPage(result);
      })
      .catch((error: unknown) => onError(errorMessage(error)));
    return () => {
      active = false;
    };
  }, [kind, family, offset, onError]);

  function chooseKind(next: Kind) {
    setKind(next);
    setFamily("");
    setOffset(0);
  }

  function chooseFamily(next: string) {
    setFamily(next);
    setOffset(0);
  }

  async function open(id: string) {
    try {
      setDetail(await api.scenario(id));
    } catch (error) {
      onError(errorMessage(error));
    }
  }

  const options = families.filter((item) => kind === "all" || item.is_attack === (kind === "attack"));
  const pages = totalPages(page.total, PAGE_SIZE);
  const current = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div className="layout">
      <aside>
        <section className="card" aria-label="Scenario filters">
          <h2>Scenarios</h2>
          <label>
            Type
            <select value={kind} onChange={(event) => chooseKind(event.target.value as Kind)}>
              <option value="all">All</option>
              <option value="attack">Attacks</option>
              <option value="benign">Benign tasks</option>
            </select>
          </label>
          <label>
            Family
            <select value={family} onChange={(event) => chooseFamily(event.target.value)}>
              <option value="">All families</option>
              {options.map((item) => (
                <option key={item.family} value={item.family}>
                  {`${familyLabel(item.family)} (${item.count})`}
                </option>
              ))}
            </select>
          </label>
        </section>
        <p className="muted">{`${page.total} scenarios, page ${current} of ${pages}`}</p>
        <ul className="runs">
          {page.items.map((scenario) => {
            const selected = detail?.id === scenario.id;
            return (
              <li key={scenario.id}>
                <button
                  type="button"
                  className={selected ? "run selected" : "run"}
                  aria-pressed={selected}
                  onClick={() => void open(scenario.id)}
                >
                  <span className="run-title">{scenario.id}</span>
                  <span className="run-defense">{familyLabel(scenario.family)}</span>
                  <span className="run-defense">{truncate(scenario.task, 70)}</span>
                </button>
              </li>
            );
          })}
        </ul>
        <div className="pager">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            Previous
          </button>
          <button
            type="button"
            disabled={offset + PAGE_SIZE >= page.total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Next
          </button>
        </div>
      </aside>
      <main>
        {detail ? (
          <>
            <ScenarioView scenario={detail} />
            <ComparePanel scenarioId={detail.id} onError={onError} onChanged={onChanged} />
          </>
        ) : (
          <p className="empty">Select a scenario to inspect it.</p>
        )}
      </main>
    </div>
  );
}
