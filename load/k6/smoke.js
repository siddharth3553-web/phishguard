import http from "k6/http";
import { check, sleep } from "k6";

const BASE = __ENV.BASE_URL || "http://localhost:8000";

export const options = {
  vus: 5,
  duration: "20s",
  thresholds: {
    http_req_duration: ["p(95)<500"],
    http_req_failed: ["rate<0.05"],
  },
};

export default function () {
  const health = http.get(`${BASE}/health`);
  check(health, { "health 200": (r) => r.status === 200 });

  const res = http.post(
    `${BASE}/api/v1/urls/scans`,
    JSON.stringify({ url: "https://www.wikipedia.org/wiki/Python" }),
    { headers: { "Content-Type": "application/json" } },
  );
  check(res, { "scan 201": (r) => r.status === 201 });
  sleep(0.2);
}
