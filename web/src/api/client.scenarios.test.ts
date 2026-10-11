import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

function stub(body: unknown) {
  const mock = vi.fn(
    async (_url: string, _init?: RequestInit) => new Response(JSON.stringify(body), { status: 200 }),
  );
  vi.stubGlobal("fetch", mock);
  return mock;
}

describe("scenario endpoints", () => {
  it("fetches one scenario and the family list", async () => {
    const mock = stub({});
    await api.scenario("atk-0001");
    await api.families();
    expect(mock.mock.calls[0]?.[0]).toBe("/api/scenarios/atk-0001");
    expect(mock.mock.calls[1]?.[0]).toBe("/api/families");
  });

  it("encodes the family filter", async () => {
    const mock = stub({ total: 0, items: [] });
    await api.scenarios({ family: "attack/shell_exec", attack: true, limit: 25, offset: 50 });
    expect(mock.mock.calls[0]?.[0]).toBe(
      "/api/scenarios?family=attack%2Fshell_exec&attack=true&limit=25&offset=50",
    );
  });
});
