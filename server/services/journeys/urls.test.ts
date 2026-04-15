import { describe, it, expect } from "vitest";
import { buildWebAppUrl, detectWebScheme, normalizeTarget } from "./urls";

describe("buildWebAppUrl", () => {
  it("omits port 80 for http", () => {
    expect(buildWebAppUrl("example.com", 80, "http")).toBe("http://example.com");
  });
  it("omits port 443 for https", () => {
    expect(buildWebAppUrl("example.com", "443", "https")).toBe("https://example.com");
  });
  it("keeps non-default http port", () => {
    expect(buildWebAppUrl("example.com", 8080, "http")).toBe("http://example.com:8080");
  });
  it("keeps non-default https port", () => {
    expect(buildWebAppUrl("example.com", 8443, "https")).toBe("https://example.com:8443");
  });
  it("strips /tcp suffix from port string", () => {
    expect(buildWebAppUrl("example.com", "8080/tcp", "http")).toBe("http://example.com:8080");
  });
});

describe("detectWebScheme", () => {
  it("detects https via port 443", () => {
    expect(detectWebScheme(443)).toBe("https");
  });
  it("detects https via port 8443", () => {
    expect(detectWebScheme(8443)).toBe("https");
  });
  it("detects https via service name", () => {
    expect(detectWebScheme(9999, "ssl/http")).toBe("https");
  });
  it("detects http via common ports", () => {
    expect(detectWebScheme(80)).toBe("http");
    expect(detectWebScheme(8080)).toBe("http");
  });
  it("returns null for non-web ports", () => {
    expect(detectWebScheme(22)).toBeNull();
    expect(detectWebScheme(3306, "mysql")).toBeNull();
  });
  it("strips /tcp suffix", () => {
    expect(detectWebScheme("443/tcp")).toBe("https");
  });
});

describe("normalizeTarget", () => {
  it("strips trailing slash on root path", () => {
    expect(normalizeTarget("http://example.com/")).toBe("http://example.com");
  });
  it("removes default http port 80", () => {
    expect(normalizeTarget("http://example.com:80")).toBe("http://example.com");
  });
  it("removes default https port 443", () => {
    expect(normalizeTarget("https://example.com:443/")).toBe("https://example.com");
  });
  it("keeps non-default port", () => {
    expect(normalizeTarget("http://example.com:8080")).toBe("http://example.com:8080/");
  });
  it("rejects non-http/https", () => {
    expect(normalizeTarget("ftp://example.com")).toBeNull();
  });
  it("rejects invalid URLs", () => {
    expect(normalizeTarget("not a url")).toBeNull();
    expect(normalizeTarget("")).toBeNull();
    expect(normalizeTarget(null)).toBeNull();
    expect(normalizeTarget(undefined)).toBeNull();
  });
  it("preserves path and query", () => {
    expect(normalizeTarget("http://example.com/api/v1?x=1")).toBe("http://example.com/api/v1?x=1");
  });
});
