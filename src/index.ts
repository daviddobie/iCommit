import express from "express";
import mysql from "mysql2/promise";

const app = express();
const port = Number(process.env.PORT ?? 3000);

app.disable("x-powered-by");
app.use(express.json({ limit: "32kb" }));

type DatabaseState = "connected" | "unconfigured" | "unavailable";

async function checkDatabase(): Promise<DatabaseState> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    return "unconfigured";
  }

  let connection: mysql.Connection | undefined;
  try {
    connection = await mysql.createConnection(databaseUrl);
    await connection.query("SELECT 1");
    return "connected";
  } catch {
    return "unavailable";
  } finally {
    await connection?.end();
  }
}

app.get("/", (_request, response) => {
  response.status(200).json({
    service: "icommit-api",
    message: "iCommit API is ready for configuration.",
  });
});

app.get("/health", async (_request, response) => {
  const database = await checkDatabase();
  const isHealthy = database !== "unavailable";

  response.status(isHealthy ? 200 : 503).json({
    status: isHealthy ? "ok" : "degraded",
    service: "icommit-api",
    database,
  });
});

app.use((_request, response) => {
  response.status(404).json({ error: "Route not found" });
});

app.listen(port, "0.0.0.0", () => {
  console.log(`iCommit API listening on port ${port}`);
});
