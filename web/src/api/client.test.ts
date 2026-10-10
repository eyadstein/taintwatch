import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, buildQuery, errorMessage } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

function stub(body: unknown, status = 200) {
  const mock = vi.fn(
    async (_url: string, _init?: RequestInit) =>
      new Response(body === undefined ? null : JSON.stringify(body), { status }),
  );
  vi.stubGlobal("fetch", mock);
  return mock;
}

describe("buildQuery", () => {
  it("skips undefined values and keeps order", () => {
    expect(buildQuery({ limit: 10, defense: "none", skip: undefined })).toBe("?limit=10&defense=none");
    expect(buildQuery({})).toBe("");
    expect(buildQuery({ attack: false })).toBe("?attack=false");
  });
});

describe("api client", () => {
  it("parses a JSON response", async () => {
    const mock = stub({ status: "ok", scenarios: 3, runs: 1 });
    expect(await api.health()).toEqual({ status: "ok", scenarios: 3, runs: 1 });
    expect(mock.mock.calls[0]?.[0]).toBe("/api/health");
  });

  it("builds list URLs", async () => {
    const mock = stub({ total: 0, items: [] });
    await api.listRuns({ limit: 10, defense: "none" });
    expect(mock.mock.calls[0]?.[0]).toBe("/api/runs?limit=10&defense=none");
    await api.scenarios({ attack: true, limit: 500 });
    expect(mock.mock.calls[1]?.[0]).toBe("/api/scenarios?attack=true&limit=500");
  });

  it("posts a run request as JSON", async () => {
    const mock = stub({ id: 1 });
    await api.createRun({ scenario_id: "atk-0000", defense: "none", confirm: true });
    const init = mock.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({
      scenario_id: "atk-0000",
      defense: "none",
      confirm: true,
    });
  });

  it("turns error responses into ApiError with the server detail", async () => {
    stub({ detail: "unknown run 9" }, 404);
    const failure = await api.getRun(9).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).status).toBe(404);
    expect(errorMessage(failure)).toBe("unknown run 9");
  });

  it("handles 204 responses", async () => {
    stub(undefined, 204);
    expect(await api.deleteRun(1)).toBeUndefined();
  });

  it("formats non-Error values", () => {
    expect(errorMessage("boom")).toBe("boom");
  });
});
