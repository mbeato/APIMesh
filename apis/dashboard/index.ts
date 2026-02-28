import { Hono } from "hono";
import { cors } from "hono/cors";
import db, { getRevenueByApi, getTotalRevenue } from "../../shared/db";

const app = new Hono();
const PORT = 3000;

app.use("*", cors());

app.get("/", (c) => {
  const revenue7d = getTotalRevenue(7);
  const revenue30d = getTotalRevenue(30);
  const apis = db.query("SELECT * FROM api_registry WHERE status = 'active'").all();
  const revenueByApi = getRevenueByApi(7);

  return c.json({
    status: "operational",
    wallet: "0x52e5B77b02F115FD7fC2D7E740971AEa85880808",
    revenue: {
      last_7_days: revenue7d,
      last_30_days: revenue30d,
      by_api: revenueByApi,
    },
    apis,
    timestamp: new Date().toISOString(),
  });
});

app.get("/health", (c) => c.json({ status: "ok" }));

console.log(`dashboard listening on port ${PORT}`);

export default {
  port: PORT,
  fetch: app.fetch,
};
