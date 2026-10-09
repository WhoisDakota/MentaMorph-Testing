//POST /organizations
//API Gateway HTTP API (FLOW: JWT authorizer backed by Cognito user pool) -> Lambda (Node 20) -> RDS Proxy -> Postgres
//
//npm i pg @aws-sdk/client-secrets-manager
//npm i -D @types/pg @types/aws-lambda

import { createHash, randomUUID } from "node:crypto";
import { Pool, PoolClient } from "pg";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import type { APIGatewayProxyEventV2WithJWTAuthorizer, APIGatewayProxyResultV2 } from "aws-lambda";

//DB connection (reused across warm invocations)

const secrets = new SecretsManagerClient({});
let pool: Pool | undefined;

async function getPool(): Promise<Pool> {
  if (pool) return pool;
  const res = await secrets.send(new GetSecretValueCommand({ SecretId: process.env.DB_SECRET_ARN! }));
  const s = JSON.parse(res.SecretString!);
  pool = new Pool({
    host: process.env.DB_HOST, //RDS Proxy endpoint
    port: 5432,
    database: process.env.DB_NAME,
    user: s.username,
    password: s.password,
    ssl: { rejectUnauthorized: true },
    max: 2, //Lambda: keep this small, let RDS Proxy do the pooling
  });
  return pool;
}

//Validation

//Extend this list or load it from a maintained package.
const FREE_MAIL_DOMAINS = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
  "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
]);

const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function parseInput(body: string | undefined): { name: string; domain: string } {
  let raw: any;
  try {
    raw = JSON.parse(body ?? "");
  } catch {
    throw new HttpError(400, "Body must be valid JSON");
  }

  const name = typeof raw?.name === "string" ? raw.name.trim() : "";
  if (name.length < 1 || name.length > 200) throw new HttpError(422, "name must be 1-200 characters");

  let domain = typeof raw?.domain === "string" ? raw.domain.trim().toLowerCase() : "";
  domain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
  if (!DOMAIN_RE.test(domain)) throw new HttpError(422, "domain is not a valid domain name");
  if (FREE_MAIL_DOMAINS.has(domain)) throw new HttpError(422, "Free email domains cannot be used for an organization");

  return { name, domain };
}

//Handler

export const handler = async (
  event: APIGatewayProxyEventV2WithJWTAuthorizer
): Promise<APIGatewayProxyResultV2> => {
  try {
    const userId = event.requestContext.authorizer.jwt.claims["sub"] as string | undefined;
    if (!userId) throw new HttpError(401, "Unauthorized");

    /*Optional: gate who may create orgs (e.g. a Cognito group or custom claim)
    //if (!String(event.requestContext.authorizer.jwt.claims["cognito:groups"] ?? "").includes("org-creators"))
    throw new HttpError(403, "Not allowed to create organizations");*/

    const { name, domain } = parseInput(event.body);
    const idempotencyKey = event.headers?.["idempotency-key"];
    if (idempotencyKey && idempotencyKey.length > 128) throw new HttpError(400, "Idempotency-Key too long");

    const requestHash = createHash("sha256").update(JSON.stringify({ name, domain })).digest("hex");
    const orgId = randomUUID();

    const client = await (await getPool()).connect();
    try {
      await client.query("BEGIN");

      //Idempotency: first writer wins, retries get the original result back.
      if (idempotencyKey) {
        const ins = await client.query(
          `INSERT INTO idempotency_keys (user_id, key, request_hash, org_id)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (user_id, key) DO NOTHING
           RETURNING org_id`,
          [userId, idempotencyKey, requestHash, orgId]
        );
        if (ins.rowCount === 0) {
          const prev = await client.query(
            `SELECT org_id, request_hash FROM idempotency_keys WHERE user_id = $1 AND key = $2`,
            [userId, idempotencyKey]
          );
          await client.query("ROLLBACK");
          if (prev.rows[0].request_hash !== requestHash) {
            throw new HttpError(422, "Idempotency-Key was already used with a different request");
          }
          return await respondWithExisting(client, prev.rows[0].org_id);
        }
      }

      const org = await createOrg(client, { orgId, name, domain, userId });
      await client.query("COMMIT");
      return json(201, org, { Location: `/organizations/${org.org_id}` });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  } catch (err: any) {
    if (err instanceof HttpError) return json(err.status, { error: err.message });
    //Unique violation on the domain index
    if (err?.code === "23505" && String(err?.constraint).includes("domain")) {
      return json(409, { error: "An organization with this domain already exists" });
    }
    console.error("create organization failed", err);
    return json(500, { error: "Internal server error" });
  }
};

//Helper functions

async function createOrg(
  client: PoolClient,
  p: { orgId: string; name: string; domain: string; userId: string }
) {
  const { rows } = await client.query(
    `INSERT INTO organizations (org_id, name, domain, created_by)
     VALUES ($1, $2, $3, $4)
     RETURNING org_id, name, domain, domain_verified, status, created_at`,
    [p.orgId, p.name, p.domain, p.userId]
  );

  //Creator becomes the first owner so the org is never admin-less.
  await client.query(
    `INSERT INTO memberships (org_id, user_id, role, created_by) VALUES ($1, $2, 'owner', $2)`,
    [p.orgId, p.userId]
  );

  await client.query(
    `INSERT INTO audit_log (org_id, actor_id, action, details) VALUES ($1, $2, 'org.created', $3)`,
    [p.orgId, p.userId, JSON.stringify({ name: p.name, domain: p.domain })]
  );

  return { ...rows[0], role: "owner" };
}

async function respondWithExisting(client: PoolClient, orgId: string): Promise<APIGatewayProxyResultV2> {
  const { rows } = await client.query(
    `SELECT org_id, name, domain, domain_verified, status, created_at FROM organizations WHERE org_id = $1`,
    [orgId]
  );
  return json(200, { ...rows[0], role: "owner" });
}

function json(statusCode: number, body: unknown, headers: Record<string, string> = {}): APIGatewayProxyResultV2 {
  return {
    statusCode,
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  };
}
