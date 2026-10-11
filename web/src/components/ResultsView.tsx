import { useEffect, useState } from "react";
import { ApiError, api, errorMessage } from "../api/client";
import type { ResultsData } from "../api/types";
import { ResultsDashboard } from "./ResultsDashboard";

interface Props {
  onError: (message: string) => void;
}

export function ResultsView({ onError }: Props) {
  const [data, setData] = useState<ResultsData | null>(null);
  const [missing, setMissing] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api
      .results()
      .then((result) => {
        if (active) setData(result);
      })
      .catch((error: unknown) => {
        if (!active) return;
        if (error instanceof ApiError && error.status === 404) {
          setMissing(error.message);
        } else {
          onError(errorMessage(error));
        }
      });
    return () => {
      active = false;
    };
  }, [onError]);

  if (missing) {
    return <p className="empty">{missing}</p>;
  }
  if (!data) {
    return <p className="empty">Loading results...</p>;
  }
  return <ResultsDashboard data={data} />;
}
