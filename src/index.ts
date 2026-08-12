import express, { type NextFunction, type Request, type Response } from "express";
import mysql, { type Pool, type PoolConnection, type RowDataPacket } from "mysql2/promise";

import { hashPassword, signAccessToken, verifyAccessToken, verifyPassword } from "./security.js";

const app = express();
const port = Number(process.env.PORT ?? 3000);
const jwtSecret = process.env.JWT_SECRET;

type DatabaseState = "connected" | "unconfigured" | "unavailable";
type AuthState = "configured" | "unconfigured";
type SessionStatus = "pending" | "active" | "ended" | "completed";

type AuthenticatedRequest = Request & { userId?: number };
type UserRow = RowDataPacket & { id: number; email: string; displayName: string };
type RelationshipRow = RowDataPacket & { id: number; userAId: number; userBId: number };
type SessionRow = RowDataPacket & {
  id: number;
  relationshipId: number;
  createdByUserId: number;
  durationSeconds: number;
  status: SessionStatus;
  startedAt: Date | null;
  endsAt: Date | null;
  endedAt: Date | null;
};

let pool: Pool | undefined;
let schemaPromise: Promise<void> | undefined;

function getPool(): Pool | undefined {
  if (!process.env.DATABASE_URL) {
    return undefined;
  }
  if (!pool) {
    pool = mysql.createPool({
      uri: process.env.DATABASE_URL,
      connectionLimit: 5,
      waitForConnections: true,
      timezone: "Z",
    });
  }
  return pool;
}

async function ensureSchema(): Promise<void> {
  const database = getPool();
  if (!database) {
    throw new Error("DATABASE_UNCONFIGURED");
  }
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await database.query(`CREATE TABLE IF NOT EXISTS users (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(320) NOT NULL UNIQUE,
        displayName VARCHAR(64) NOT NULL,
        passwordHash VARCHAR(255) NOT NULL,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB`);
      await database.query(`CREATE TABLE IF NOT EXISTS pairing_invites (
        code CHAR(8) NOT NULL PRIMARY KEY,
        createdByUserId BIGINT UNSIGNED NOT NULL,
        expiresAt DATETIME NOT NULL,
        acceptedByUserId BIGINT UNSIGNED NULL,
        acceptedAt DATETIME NULL,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_pairing_invites_creator (createdByUserId),
        CONSTRAINT fk_pairing_invites_creator FOREIGN KEY (createdByUserId) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB`);
      await database.query(`CREATE TABLE IF NOT EXISTS relationships (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        userAId BIGINT UNSIGNED NOT NULL,
        userBId BIGINT UNSIGNED NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'active',
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        endedAt DATETIME NULL,
        INDEX idx_relationships_user_a (userAId),
        INDEX idx_relationships_user_b (userBId),
        CONSTRAINT fk_relationships_user_a FOREIGN KEY (userAId) REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT fk_relationships_user_b FOREIGN KEY (userBId) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB`);
      await database.query(`CREATE TABLE IF NOT EXISTS commitment_sessions (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        relationshipId BIGINT UNSIGNED NOT NULL,
        createdByUserId BIGINT UNSIGNED NOT NULL,
        durationSeconds INT UNSIGNED NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'pending',
        startedAt DATETIME NULL,
        endsAt DATETIME NULL,
        endedAt DATETIME NULL,
        endedByUserId BIGINT UNSIGNED NULL,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_sessions_relationship_status (relationshipId, status),
        CONSTRAINT fk_sessions_relationship FOREIGN KEY (relationshipId) REFERENCES relationships(id) ON DELETE CASCADE,
        CONSTRAINT fk_sessions_creator FOREIGN KEY (createdByUserId) REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT fk_sessions_ender FOREIGN KEY (endedByUserId) REFERENCES users(id) ON DELETE SET NULL
      ) ENGINE=InnoDB`);
      await database.query(`CREATE TABLE IF NOT EXISTS session_acknowledgements (
        sessionId BIGINT UNSIGNED NOT NULL,
        userId BIGINT UNSIGNED NOT NULL,
        acknowledgedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (sessionId, userId),
        CONSTRAINT fk_ack_session FOREIGN KEY (sessionId) REFERENCES commitment_sessions(id) ON DELETE CASCADE,
        CONSTRAINT fk_ack_user FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB`);
    })();
  }
  return schemaPromise;
}

async function withConnection<T>(work: (connection: PoolConnection) => Promise<T>): Promise<T> {
  await ensureSchema();
  const database = getPool();
  if (!database) {
    throw new Error("DATABASE_UNCONFIGURED");
  }
  const connection = await database.getConnection();
  try {
    return await work(connection);
  } finally {
    connection.release();
  }
}

async function checkDatabase(): Promise<DatabaseState> {
  if (!process.env.DATABASE_URL) {
    return "unconfigured";
  }
  try {
    await ensureSchema();
    const database = getPool();
    await database?.query("SELECT 1");
    return "connected";
  } catch {
    return "unavailable";
  }
}

function normalizeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 320 ? email : null;
}

function normalizeDisplayName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const name = value.trim();
  return name.length >= 1 && name.length <= 64 ? name : null;
}

function normalizePassword(value: unknown): string | null {
  return typeof value === "string" && value.length >= 12 && value.length <= 128 ? value : null;
}

function parseDuration(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 300 && value <= 14_400 ? value : null;
}

function randomInviteCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return Array.from({ length: 8 }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join("");
}

async function getActiveRelationship(connection: PoolConnection, userId: number): Promise<RelationshipRow | undefined> {
  const [rows] = await connection.query<RelationshipRow[]>(
    "SELECT id, userAId, userBId FROM relationships WHERE status = 'active' AND (userAId = ? OR userBId = ?) LIMIT 1",
    [userId, userId],
  );
  return rows[0];
}

async function getOwnedSession(connection: PoolConnection, userId: number, sessionId: number): Promise<SessionRow | undefined> {
  const [rows] = await connection.query<SessionRow[]>(
    `SELECT s.id, s.relationshipId, s.createdByUserId, s.durationSeconds, s.status, s.startedAt, s.endsAt, s.endedAt
     FROM commitment_sessions s
     JOIN relationships r ON r.id = s.relationshipId
     WHERE s.id = ? AND r.status = 'active' AND (r.userAId = ? OR r.userBId = ?) LIMIT 1`,
    [sessionId, userId, userId],
  );
  return rows[0];
}

function userResponse(user: UserRow) {
  return { id: user.id, email: user.email, displayName: user.displayName };
}

function sessionResponse(session: SessionRow) {
  return {
    id: session.id,
    relationshipId: session.relationshipId,
    durationSeconds: session.durationSeconds,
    status: session.status,
    startedAt: session.startedAt,
    endsAt: session.endsAt,
    endedAt: session.endedAt,
  };
}

function error(response: Response, status: number, code: string, message: string) {
  return response.status(status).json({ error: { code, message } });
}

function requireAuth(request: AuthenticatedRequest, response: Response, next: NextFunction) {
  if (!jwtSecret) {
    return error(response, 503, "AUTH_UNCONFIGURED", "The API authentication secret is not configured.");
  }
  const header = request.header("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
  const payload = token ? verifyAccessToken(token, jwtSecret) : null;
  if (!payload) {
    return error(response, 401, "UNAUTHORIZED", "A valid access token is required.");
  }
  request.userId = payload.userId;
  return next();
}

app.disable("x-powered-by");
app.use(express.json({ limit: "32kb" }));
app.use((_request, response, next) => {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (_request.method === "OPTIONS") return response.sendStatus(204);
  return next();
});

app.get("/", (_request, response) => {
  response.status(200).json({
    service: "icommit-api",
    message: "iCommit API is ready for connected commitments.",
  });
});

app.get("/health", async (_request, response) => {
  const database = await checkDatabase();
  response.status(database === "unavailable" ? 503 : 200).json({
    status: database === "unavailable" ? "degraded" : "ok",
    service: "icommit-api",
    database,
    auth: jwtSecret ? ("configured" as AuthState) : ("unconfigured" as AuthState),
  });
});

app.post("/auth/register", async (request, response) => {
  const email = normalizeEmail(request.body?.email);
  const displayName = normalizeDisplayName(request.body?.displayName);
  const password = normalizePassword(request.body?.password);
  if (!email || !displayName || !password) {
    return error(response, 400, "INVALID_INPUT", "Provide a valid email, display name, and password of at least 12 characters.");
  }
  if (!jwtSecret) {
    return error(response, 503, "AUTH_UNCONFIGURED", "The API authentication secret is not configured.");
  }

  try {
    const passwordHash = await hashPassword(password);
    const user = await withConnection(async (connection) => {
      const [existing] = await connection.query<UserRow[]>("SELECT id, email, displayName FROM users WHERE email = ? LIMIT 1", [email]);
      if (existing[0]) return undefined;
      const [result] = await connection.execute<mysql.ResultSetHeader>(
        "INSERT INTO users (email, displayName, passwordHash) VALUES (?, ?, ?)",
        [email, displayName, passwordHash],
      );
      const [rows] = await connection.query<UserRow[]>("SELECT id, email, displayName FROM users WHERE id = ?", [result.insertId]);
      return rows[0];
    });
    if (!user) {
      return error(response, 409, "EMAIL_IN_USE", "An account already uses this email address.");
    }
    return response.status(201).json({ user: userResponse(user), accessToken: signAccessToken(user.id, jwtSecret) });
  } catch {
    return error(response, 503, "DATABASE_UNAVAILABLE", "The account service is temporarily unavailable.");
  }
});

app.post("/auth/login", async (request, response) => {
  const email = normalizeEmail(request.body?.email);
  const password = typeof request.body?.password === "string" ? request.body.password : null;
  if (!email || !password) {
    return error(response, 400, "INVALID_INPUT", "Provide an email and password.");
  }
  if (!jwtSecret) {
    return error(response, 503, "AUTH_UNCONFIGURED", "The API authentication secret is not configured.");
  }

  try {
    const result = await withConnection(async (connection) => {
      const [rows] = await connection.query<(UserRow & { passwordHash: string })[]>(
        "SELECT id, email, displayName, passwordHash FROM users WHERE email = ? LIMIT 1",
        [email],
      );
      const user = rows[0];
      return user && (await verifyPassword(password, user.passwordHash)) ? user : undefined;
    });
    if (!result) {
      return error(response, 401, "INVALID_CREDENTIALS", "The email or password is incorrect.");
    }
    return response.status(200).json({ user: userResponse(result), accessToken: signAccessToken(result.id, jwtSecret) });
  } catch {
    return error(response, 503, "DATABASE_UNAVAILABLE", "The account service is temporarily unavailable.");
  }
});

app.get("/state", requireAuth, async (request: AuthenticatedRequest, response) => {
  const userId = request.userId!;
  try {
    const state = await withConnection(async (connection) => {
      const relationship = await getActiveRelationship(connection, userId);
      if (!relationship) return { partner: null, relationship: null, session: null };
      const partnerId = relationship.userAId === userId ? relationship.userBId : relationship.userAId;
      const [partnerRows] = await connection.query<UserRow[]>("SELECT id, email, displayName FROM users WHERE id = ?", [partnerId]);
      await connection.execute(
        "UPDATE commitment_sessions SET status = 'completed', endedAt = NOW() WHERE relationshipId = ? AND status = 'active' AND endsAt <= NOW()",
        [relationship.id],
      );
      const [sessionRows] = await connection.query<SessionRow[]>(
        `SELECT id, relationshipId, createdByUserId, durationSeconds, status, startedAt, endsAt, endedAt
         FROM commitment_sessions WHERE relationshipId = ? AND status IN ('pending', 'active') ORDER BY id DESC LIMIT 1`,
        [relationship.id],
      );
      return {
        partner: partnerRows[0] ? userResponse(partnerRows[0]) : null,
        relationship: { id: relationship.id },
        session: sessionRows[0] ? sessionResponse(sessionRows[0]) : null,
      };
    });
    return response.status(200).json(state);
  } catch {
    return error(response, 503, "DATABASE_UNAVAILABLE", "Unable to load shared commitment state.");
  }
});

app.post("/pairing/invites", requireAuth, async (request: AuthenticatedRequest, response) => {
  const userId = request.userId!;
  try {
    const invite = await withConnection(async (connection) => {
      const relationship = await getActiveRelationship(connection, userId);
      if (relationship) return { alreadyPaired: true as const };
      let code = randomInviteCode();
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const [existing] = await connection.query<RowDataPacket[]>("SELECT code FROM pairing_invites WHERE code = ?", [code]);
        if (!existing[0]) break;
        code = randomInviteCode();
      }
      await connection.execute(
        "INSERT INTO pairing_invites (code, createdByUserId, expiresAt) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE))",
        [code, userId],
      );
      return { code, expiresInSeconds: 900 };
    });
    if ("alreadyPaired" in invite) return error(response, 409, "ALREADY_PAIRED", "End the existing pairing before creating a new invite.");
    return response.status(201).json(invite);
  } catch {
    return error(response, 503, "DATABASE_UNAVAILABLE", "Unable to create a pairing invitation.");
  }
});

app.post("/pairing/accept", requireAuth, async (request: AuthenticatedRequest, response) => {
  const code = typeof request.body?.code === "string" ? request.body.code.trim().toUpperCase() : "";
  const userId = request.userId!;
  if (!/^[A-Z0-9]{8}$/.test(code)) return error(response, 400, "INVALID_INPUT", "Provide an eight-character pairing code.");

  try {
    const result = await withConnection(async (connection) => {
      await connection.beginTransaction();
      try {
        const currentRelationship = await getActiveRelationship(connection, userId);
        if (currentRelationship) {
          await connection.rollback();
          return { alreadyPaired: true as const };
        }
        const [inviteRows] = await connection.query<(RowDataPacket & { createdByUserId: number; expiresAt: Date; acceptedByUserId: number | null })[]>(
          "SELECT createdByUserId, expiresAt, acceptedByUserId FROM pairing_invites WHERE code = ? FOR UPDATE",
          [code],
        );
        const invite = inviteRows[0];
        if (!invite || invite.acceptedByUserId || invite.expiresAt <= new Date() || invite.createdByUserId === userId) {
          await connection.rollback();
          return { invalidInvite: true as const };
        }
        const inviterRelationship = await getActiveRelationship(connection, invite.createdByUserId);
        if (inviterRelationship) {
          await connection.rollback();
          return { inviterPaired: true as const };
        }
        const [insert] = await connection.execute<mysql.ResultSetHeader>(
          "INSERT INTO relationships (userAId, userBId) VALUES (?, ?)",
          [invite.createdByUserId, userId],
        );
        await connection.execute("UPDATE pairing_invites SET acceptedByUserId = ?, acceptedAt = NOW() WHERE code = ?", [userId, code]);
        await connection.commit();
        return { relationshipId: insert.insertId };
      } catch (error) {
        await connection.rollback();
        throw error;
      }
    });
    if ("alreadyPaired" in result) return error(response, 409, "ALREADY_PAIRED", "End the existing pairing before accepting a new invite.");
    if ("invalidInvite" in result) return error(response, 404, "INVALID_INVITE", "That invitation is invalid, expired, or already used.");
    if ("inviterPaired" in result) return error(response, 409, "INVITER_ALREADY_PAIRED", "The invitation creator is already paired.");
    return response.status(201).json(result);
  } catch {
    return error(response, 503, "DATABASE_UNAVAILABLE", "Unable to accept the pairing invitation.");
  }
});

app.post("/sessions", requireAuth, async (request: AuthenticatedRequest, response) => {
  const durationSeconds = parseDuration(request.body?.durationSeconds);
  const userId = request.userId!;
  if (!durationSeconds) return error(response, 400, "INVALID_INPUT", "Choose a duration between 5 minutes and 4 hours.");
  try {
    const session = await withConnection(async (connection) => {
      const relationship = await getActiveRelationship(connection, userId);
      if (!relationship) return undefined;
      const [activeRows] = await connection.query<RowDataPacket[]>(
        "SELECT id FROM commitment_sessions WHERE relationshipId = ? AND status IN ('pending', 'active') LIMIT 1",
        [relationship.id],
      );
      if (activeRows[0]) return null;
      const [insert] = await connection.execute<mysql.ResultSetHeader>(
        "INSERT INTO commitment_sessions (relationshipId, createdByUserId, durationSeconds) VALUES (?, ?, ?)",
        [relationship.id, userId, durationSeconds],
      );
      const [rows] = await connection.query<SessionRow[]>(
        "SELECT id, relationshipId, createdByUserId, durationSeconds, status, startedAt, endsAt, endedAt FROM commitment_sessions WHERE id = ?",
        [insert.insertId],
      );
      return rows[0];
    });
    if (session === undefined) return error(response, 409, "NOT_PAIRED", "Pair with a consenting partner before starting a commitment.");
    if (session === null) return error(response, 409, "SESSION_IN_PROGRESS", "Finish the current commitment before starting another.");
    return response.status(201).json({ session: sessionResponse(session) });
  } catch {
    return error(response, 503, "DATABASE_UNAVAILABLE", "Unable to create the commitment session.");
  }
});

app.post("/sessions/:id/acknowledge", requireAuth, async (request: AuthenticatedRequest, response) => {
  const sessionId = Number(request.params.id);
  const userId = request.userId!;
  if (!Number.isInteger(sessionId) || sessionId <= 0) return error(response, 400, "INVALID_INPUT", "Use a valid commitment session id.");
  try {
    const session = await withConnection(async (connection) => {
      await connection.beginTransaction();
      try {
        const ownedSession = await getOwnedSession(connection, userId, sessionId);
        if (!ownedSession || ownedSession.status !== "pending") {
          await connection.rollback();
          return undefined;
        }
        await connection.execute("INSERT IGNORE INTO session_acknowledgements (sessionId, userId) VALUES (?, ?)", [sessionId, userId]);
        const [ackRows] = await connection.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM session_acknowledgements WHERE sessionId = ?", [sessionId]);
        if (Number(ackRows[0].count) >= 2) {
          await connection.execute(
            "UPDATE commitment_sessions SET status = 'active', startedAt = NOW(), endsAt = DATE_ADD(NOW(), INTERVAL durationSeconds SECOND) WHERE id = ? AND status = 'pending'",
            [sessionId],
          );
        }
        const [rows] = await connection.query<SessionRow[]>(
          "SELECT id, relationshipId, createdByUserId, durationSeconds, status, startedAt, endsAt, endedAt FROM commitment_sessions WHERE id = ?",
          [sessionId],
        );
        await connection.commit();
        return rows[0];
      } catch (error) {
        await connection.rollback();
        throw error;
      }
    });
    if (!session) return error(response, 404, "SESSION_NOT_PENDING", "This pending session is not available to acknowledge.");
    return response.status(200).json({ session: sessionResponse(session) });
  } catch {
    return error(response, 503, "DATABASE_UNAVAILABLE", "Unable to acknowledge the commitment session.");
  }
});

app.post("/sessions/:id/end", requireAuth, async (request: AuthenticatedRequest, response) => {
  const sessionId = Number(request.params.id);
  const userId = request.userId!;
  if (!Number.isInteger(sessionId) || sessionId <= 0) return error(response, 400, "INVALID_INPUT", "Use a valid commitment session id.");
  try {
    const session = await withConnection(async (connection) => {
      const ownedSession = await getOwnedSession(connection, userId, sessionId);
      if (!ownedSession || !["pending", "active"].includes(ownedSession.status)) return undefined;
      await connection.execute("UPDATE commitment_sessions SET status = 'ended', endedAt = NOW(), endedByUserId = ? WHERE id = ?", [userId, sessionId]);
      const [rows] = await connection.query<SessionRow[]>(
        "SELECT id, relationshipId, createdByUserId, durationSeconds, status, startedAt, endsAt, endedAt FROM commitment_sessions WHERE id = ?",
        [sessionId],
      );
      return rows[0];
    });
    if (!session) return error(response, 404, "SESSION_NOT_ACTIVE", "This commitment session is not available to end.");
    return response.status(200).json({ session: sessionResponse(session) });
  } catch {
    return error(response, 503, "DATABASE_UNAVAILABLE", "Unable to end the commitment session.");
  }
});

app.use((_request, response) => {
  response.status(404).json({ error: { code: "NOT_FOUND", message: "Route not found." } });
});

app.listen(port, "0.0.0.0", () => {
  console.log(`iCommit API listening on port ${port}`);
});
