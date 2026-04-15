import { describe, it, expect } from "vitest";
import { buildWebAppUrl, detectWebScheme } from "./urls";

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
