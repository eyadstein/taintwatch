import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("results endpoint", () => {
  it("fetches the results", async () => {
    const mock = vi.fn(
      async (_url: string, _init?: RequestInit) =>
        new Response(JSON.stringify({ pivot: "taintwatch" }), { status: 200 }),
    );
    vi.stubGlobal("fetch", mock);
    expect(await api.results()).toEqual({ pivot: "taintwatch" });
    expect(mock.mock.calls[0]?.[0]).toBe("/api/results");
  });

  it("reports a missing results file as a 404 ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async (_url: string, _init?: RequestInit) =>
          new Response(JSON.stringify({ detail: "no results found" }), { status: 404 }),
      ),
    );
    const failure = await api.results().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).status).toBe(404);
  });
});
