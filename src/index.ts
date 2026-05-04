import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

type Severity = "error" | "warn" | "info";

type Diagnostic = {
  severity: Severity;
  category:
    | "missing_price_hint"
    | "missing_protocols"
    | "missing_402_payment_options"
    | "missing_www_authenticate"
    | "missing_input_schema"
    | "missing_challenge_id"
    | "missing_challenge_expires"
    | "missing_challenge_amount"
    | "missing_challenge_recipient"
    | "realm_origin_mismatch"
    | "request_validation_order"
    | "unknown";
  route?: string;
  message: string;
  root_cause: string;
  fix: string;
};

type OpenApiDocument = {
  openapi?: string;
  paths?: Record<string, Record<string, any>>;
  components?: Record<string, any>;
  [key: string]: any;
};

function safeJsonParse<T = any>(value: string): { ok: true; data: T } | { ok: false; error: string } {
  try {
    return { ok: true, data: JSON.parse(value) as T };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err)
    };
  }
}

function jsonText(data: unknown): string {
  return JSON.stringify(data, null, 2);
}

function textResponse(data: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: typeof data === "string" ? data : jsonText(data)
      }
    ]
  };
}

function extractRoute(line: string): string | undefined {
  const match = line.match(/(?:GET|POST|PUT|PATCH|DELETE)?\s*(\/[A-Za-z0-9/_\-{}.:]+(?:Paid|Payment)?)/);
  return match?.[1];
}

function classifyMppLine(line: string): Diagnostic {
  const severity: Severity = line.includes("[error]")
    ? "error"
    : line.includes("[warn]")
      ? "warn"
      : "info";

  const route = extractRoute(line);

  if (line.includes("has no price hint")) {
    return {
      severity,
      category: "missing_price_hint",
      route,
      message: line,
      root_cause:
        "The OpenAPI operation is marked or inferred as paid, but it does not declare x-payment-info.price, minPrice, or maxPrice.",
      fix:
        "Add x-payment-info.price to the OpenAPI operation, for example: \"x-payment-info\": { \"price\": \"0.75\", \"currency\": \"USD\", \"protocols\": [\"402\"] }."
    };
  }

  if (line.includes("does not declare supported payment protocols")) {
    return {
      severity,
      category: "missing_protocols",
      route,
      message: line,
      root_cause:
        "The OpenAPI operation does not tell agents which payment flow it accepts.",
      fix:
        "Add x-payment-info.protocols. For a true 402 payment challenge flow, use a protocol label such as [\"402\"] or your exact accepted protocol name."
    };
  }

  if (line.includes("did not return payment options in the 402 response")) {
    return {
      severity,
      category: "missing_402_payment_options",
      route,
      message: line,
      root_cause:
        "The live endpoint returns 402 but the response body does not include a usable payment challenge or payment instructions.",
      fix:
        "Return a 402 JSON body with error, challenge.id, challenge.amount, challenge.currency, challenge.expires, and payment/funding instructions."
    };
  }

  if (line.includes("WWW-Authenticate header contains no Payment challenges")) {
    return {
      severity,
      category: "missing_www_authenticate",
      route,
      message: line,
      root_cause:
        "The endpoint returns 402 without a valid WWW-Authenticate header containing a Payment challenge.",
      fix:
        "Return: WWW-Authenticate: Payment realm=\"https://your-domain.com\", method=\"your-payment-method\"."
    };
  }

  if (line.includes("missing WWW-Authenticate header on 402")) {
    return {
      severity,
      category: "request_validation_order",
      route,
      message: line,
      root_cause:
        "The endpoint may be validating request body or parameters before checking payment, causing the scanner to see a non-payment error or an incomplete 402.",
      fix:
        "Move payment/balance validation before body parsing or business validation. Return 402 with WWW-Authenticate first."
    };
  }

  if (line.includes("missing an input schema")) {
    return {
      severity,
      category: "missing_input_schema",
      route,
      message: line,
      root_cause:
        "The operation does not define requestBody or parameters, so agents cannot construct valid calls.",
      fix:
        "Add OpenAPI requestBody or parameters schema. For MCP tools, expose a clear inputSchema with required fields."
    };
  }

  if (line.includes("missing the id parameter")) {
    return {
      severity,
      category: "missing_challenge_id",
      route,
      message: line,
      root_cause:
        "The payment challenge lacks a unique id, so agents cannot correlate payment credentials to a challenge.",
      fix:
        "Add a unique challenge.id such as crypto.randomUUID() or a signed challenge identifier."
      };
  }

  if (line.includes("missing the expires parameter")) {
    return {
      severity,
      category: "missing_challenge_expires",
      route,
      message: line,
      root_cause:
        "The payment challenge lacks an RFC 3339 expiration timestamp.",
      fix:
        "Add challenge.expires using new Date(Date.now() + 5 * 60 * 1000).toISOString()."
    };
  }

  if (line.includes("missing amount in the request object")) {
    return {
      severity,
      category: "missing_challenge_amount",
      route,
      message: line,
      root_cause:
        "The payment challenge does not include a raw amount value.",
      fix:
        "Add challenge.amount. Use cents for card-style flows or raw token units for token protocols."
    };
  }

  if (line.includes("missing recipient in the request object")) {
    return {
      severity,
      category: "missing_challenge_recipient",
      route,
      message: line,
      root_cause:
        "The payment challenge does not include a recipient identifier.",
      fix:
        "Add challenge.recipient, such as your merchant account, wallet, payment account, or payment collection endpoint."
    };
  }

  if (line.includes("Payment realm") && line.includes("does not match origin host")) {
    return {
      severity,
      category: "realm_origin_mismatch",
      route,
      message: line,
      root_cause:
        "The payment realm is not the same origin as the service being scanned.",
      fix:
        "Set the realm to the canonical origin of the live service, for example: Payment realm=\"https://hawaii-conditions.vercel.app\"."
    };
  }

  return {
    severity,
    category: "unknown",
    route,
    message: line,
    root_cause:
      "The line did not match a known MPP Compliance Doctor pattern.",
    fix:
      "Inspect the OpenAPI operation and live response for payment metadata, input schema, and 402 challenge correctness."
  };
}

function summarizeDiagnostics(diagnostics: Diagnostic[]) {
  const byCategory: Record<string, number> = {};
  const byRoute: Record<string, number> = {};

  for (const d of diagnostics) {
    byCategory[d.category] = (byCategory[d.category] ?? 0) + 1;
    if (d.route) byRoute[d.route] = (byRoute[d.route] ?? 0) + 1;
  }

  const errors = diagnostics.filter((d) => d.severity === "error").length;
  const warnings = diagnostics.filter((d) => d.severity === "warn").length;
  const info = diagnostics.filter((d) => d.severity === "info").length;

  return {
    total: diagnostics.length,
    errors,
    warnings,
    info,
    byCategory,
    byRoute
  };
}

function getOperationPaymentInfo(operation: any) {
  return operation?.["x-payment-info"] ?? operation?.["xPaymentInfo"] ?? null;
}

function operationHasInputSchema(method: string, operation: any): boolean {
  if (operation?.requestBody?.content) return true;
  if (Array.isArray(operation?.parameters) && operation.parameters.length > 0) return true;

  const lower = method.toLowerCase();
  if (lower === "get" && Array.isArray(operation?.parameters)) return operation.parameters.length > 0;

  return false;
}

function isPaidOperation(operation: any): boolean {
  const paymentInfo = getOperationPaymentInfo(operation);
  if (paymentInfo) return true;

  const text = JSON.stringify(operation).toLowerCase();
  return (
    text.includes("payment") ||
    text.includes("paid") ||
    text.includes("402") ||
    text.includes("price")
  );
}

function scanOpenApiDocument(doc: OpenApiDocument) {
  const diagnostics: Diagnostic[] = [];

  if (!doc.paths || typeof doc.paths !== "object") {
    diagnostics.push({
      severity: "error",
      category: "unknown",
      message: "OpenAPI document has no valid paths object.",
      root_cause: "The OpenAPI spec is missing the paths section.",
      fix: "Add a valid OpenAPI paths object with operations."
    });

    return diagnostics;
  }

  for (const [path, methods] of Object.entries(doc.paths)) {
    for (const [method, operation] of Object.entries(methods ?? {})) {
      const normalizedMethod = method.toLowerCase();
      if (!["get", "post", "put", "patch", "delete"].includes(normalizedMethod)) continue;

      const paid = isPaidOperation(operation);
      if (!paid) continue;

      const route = `${normalizedMethod.toUpperCase()} ${path}`;
      const paymentInfo = getOperationPaymentInfo(operation);

      if (!paymentInfo) {
        diagnostics.push({
          severity: "warn",
          category: "missing_price_hint",
          route,
          message: `${route} appears paid but has no x-payment-info object.`,
          root_cause:
            "Agents and scanners cannot determine price or accepted payment flow.",
          fix:
            "Add x-payment-info with price, currency, and protocols."
        });
      } else {
        if (!paymentInfo.price && !paymentInfo.minPrice && !paymentInfo.maxPrice) {
          diagnostics.push({
            severity: "warn",
            category: "missing_price_hint",
            route,
            message: `${route} has x-payment-info but no price hint.`,
            root_cause:
              "The operation does not expose a price hint agents can budget against.",
            fix:
              "Add x-payment-info.price, or minPrice/maxPrice for variable pricing."
          });
        }

        if (!Array.isArray(paymentInfo.protocols) || paymentInfo.protocols.length === 0) {
          diagnostics.push({
            severity: "info",
            category: "missing_protocols",
            route,
            message: `${route} does not declare x-payment-info.protocols.`,
            root_cause:
              "Agents do not know which payment challenge or settlement flow is accepted.",
            fix:
              "Add x-payment-info.protocols, for example [\"402\"] or your accepted protocol labels."
          });
        }
      }

      if (!operationHasInputSchema(normalizedMethod, operation)) {
        diagnostics.push({
          severity: "warn",
          category: "missing_input_schema",
          route,
          message: `${route} is missing an input schema.`,
          root_cause:
            "No requestBody or parameters schema is defined.",
          fix:
            "Add a requestBody schema for POST-like calls or parameters for GET calls."
        });
      }

      const responses = operation?.responses ?? {};
      if (!responses["402"]) {
        diagnostics.push({
          severity: "warn",
          category: "missing_402_payment_options",
          route,
          message: `${route} does not document a 402 Payment Required response.`,
          root_cause:
            "The OpenAPI spec does not tell agents how payment failure is represented.",
          fix:
            "Add a 402 response with a JSON payment challenge schema and mention WWW-Authenticate."
        });
      }
    }
  }

  return diagnostics;
}

function validate402Response(input: {
  status?: number;
  headers?: Record<string, string>;
  body?: any;
  origin?: string;
}) {
  const diagnostics: Diagnostic[] = [];
  const headers = Object.fromEntries(
    Object.entries(input.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v])
  );

  if (input.status !== 402) {
    diagnostics.push({
      severity: "error",
      category: "missing_402_payment_options",
      message: `Expected HTTP 402 but received ${input.status ?? "undefined"}.`,
      root_cause:
        "Paid endpoints must return 402 Payment Required when payment is missing or insufficient.",
      fix:
        "Return status 402 before executing the tool or validating business input."
    });
  }

  const www = headers["www-authenticate"];
  if (!www) {
    diagnostics.push({
      severity: "error",
      category: "missing_www_authenticate",
      message: "402 response is missing WWW-Authenticate header.",
      root_cause:
        "Agents and MPP scanners rely on WWW-Authenticate to detect a Payment challenge.",
      fix:
        "Add WWW-Authenticate: Payment realm=\"https://your-domain.com\", method=\"your-payment-method\"."
    });
  } else if (!/Payment/i.test(www)) {
    diagnostics.push({
      severity: "error",
      category: "missing_www_authenticate",
      message: "WWW-Authenticate header does not contain a Payment challenge.",
      root_cause:
        "The header exists but does not advertise Payment as the auth/challenge scheme.",
      fix:
        "Use a Payment challenge in the WWW-Authenticate header."
    });
  }

  if (input.origin && www) {
    try {
      const originHost = new URL(input.origin).host;
      const realmMatch = www.match(/realm="([^"]+)"/i);
      if (realmMatch) {
        const realmHost = new URL(realmMatch[1]).host;
        if (originHost !== realmHost) {
          diagnostics.push({
            severity: "error",
            category: "realm_origin_mismatch",
            message: `Payment realm host ${realmHost} does not match origin host ${originHost}.`,
            root_cause:
              "The Payment realm should identify the same service origin that agents are calling.",
            fix:
              `Set realm to ${new URL(input.origin).origin}.`
          });
        }
      }
    } catch {
      // ignore URL parsing issues
    }
  }

  const body = input.body ?? {};
  const challenge = body.challenge ?? body.payment ?? body.payment_challenge ?? null;

  if (!challenge) {
    diagnostics.push({
      severity: "warn",
      category: "missing_402_payment_options",
      message: "402 body does not include challenge, payment, or payment_challenge object.",
      root_cause:
        "The response body does not tell agents how much to pay or how to continue.",
      fix:
        "Add a challenge object with id, amount, currency, expires, recipient or funding_url."
    });

    return diagnostics;
  }

  if (!challenge.id) {
    diagnostics.push({
      severity: "error",
      category: "missing_challenge_id",
      message: "Payment challenge is missing id.",
      root_cause:
        "Agents need a stable challenge id for correlation.",
      fix:
        "Add id: crypto.randomUUID()."
    });
  }

  if (!challenge.expires) {
    diagnostics.push({
      severity: "error",
      category: "missing_challenge_expires",
      message: "Payment challenge is missing expires.",
      root_cause:
        "Agents need to know when the challenge lapses.",
      fix:
        "Add expires as an RFC 3339 timestamp."
    });
  }

  if (!challenge.amount) {
    diagnostics.push({
      severity: "error",
      category: "missing_challenge_amount",
      message: "Payment challenge is missing amount.",
      root_cause:
        "Agents need a raw amount to determine cost.",
      fix:
        "Add amount as a string, such as \"75\" for cents or raw token units for token protocols."
    });
  }

  if (!challenge.recipient && !challenge.funding_url && !challenge.checkout_url) {
    diagnostics.push({
      severity: "warn",
      category: "missing_challenge_recipient",
      message: "Payment challenge is missing recipient, funding_url, or checkout_url.",
      root_cause:
        "Agents need to know where payment should be sent or where funds should be added.",
      fix:
        "Add recipient, funding_url, or checkout_url depending on your payment flow."
    });
  }

  return diagnostics;
}

function buildOpenApiPatch(args: {
  routes: string[];
  price: string;
  currency: string;
  protocols: string[];
  includeInputSchema: boolean;
}) {
  const patch: Record<string, any> = {};

  for (const route of args.routes) {
    const [methodRaw, ...pathParts] = route.trim().split(/\s+/);
    const method = pathParts.length > 0 ? methodRaw.toLowerCase() : "post";
    const path = pathParts.length > 0 ? pathParts.join(" ") : route.trim();

    patch[path] = patch[path] ?? {};
    patch[path][method] = {
      "x-payment-info": {
        price: args.price,
        currency: args.currency,
        protocols: args.protocols
      },
      responses: {
        "402": {
          description: "Payment Required. Returns a Payment challenge in the WWW-Authenticate header and JSON body.",
          headers: {
            "WWW-Authenticate": {
              schema: {
                type: "string",
                example: `Payment realm="https://your-domain.com", method="${args.protocols[0] ?? "402"}"`
              }
            }
          },
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["error", "challenge"],
                properties: {
                  error: {
                    type: "string",
                    example: "payment_required"
                  },
                  challenge: {
                    type: "object",
                    required: ["id", "amount", "currency", "expires"],
                    properties: {
                      id: { type: "string", example: "challenge_123" },
                      amount: { type: "string", example: args.price },
                      currency: { type: "string", example: args.currency },
                      expires: {
                        type: "string",
                        format: "date-time",
                        example: "2026-05-04T12:05:00Z"
                      },
                      recipient: {
                        type: "string",
                        example: "merchant_or_payment_account"
                      },
                      funding_url: {
                        type: "string",
                        format: "uri",
                        example: "https://your-domain.com/fund"
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    };

    if (args.includeInputSchema) {
      if (method === "get") {
        patch[path][method].parameters = [
          {
            name: "input",
            in: "query",
            required: false,
            schema: {
              type: "string"
            },
            description: "Tool input as a query parameter when applicable."
          }
        ];
      } else {
        patch[path][method].requestBody = {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: true,
                description:
                  "Replace this generic schema with the exact tool input schema for best agent compatibility."
              }
            }
          }
        };
      }
    }
  }

  return {
    explanation:
      "Apply this patch into your OpenAPI paths. Keep your existing operationId, summary, and business response schemas.",
    paths_patch: patch
  };
}

function generateNextJs402Fix(args: {
  realm: string;
  method: string;
  debugPriceCents: number;
  fixPriceCents: number;
}) {
  return `// lib/payment-required.ts
import crypto from "node:crypto";

type PaymentRequiredOptions = {
  amountCents: number;
  description: string;
  toolName: string;
};

export function paymentRequiredResponse(options: PaymentRequiredOptions) {
  const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  return new Response(
    JSON.stringify({
      error: "payment_required",
      challenge: {
        id: crypto.randomUUID(),
        type: "${args.method}",
        amount: String(options.amountCents),
        currency: "USD",
        description: options.description,
        tool: options.toolName,
        expires,
        funding_url: "${args.realm.replace(/\/$/, "")}/fund"
      }
    }),
    {
      status: 402,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "WWW-Authenticate": 'Payment realm="${args.realm}", method="${args.method}"'
      }
    }
  );
}

// lib/balance.ts
export async function hasSufficientBalance(apiKey: string | null, amountCents: number): Promise<boolean> {
  if (!apiKey) return false;

  // Production TODO:
  // 1. Look up agent account by API key.
  // 2. Confirm prepaid balance >= amountCents.
  // 3. Return true only when funds are available.
  return false;
}

export async function debitBalance(apiKey: string, amountCents: number, reason: string): Promise<void> {
  // Production TODO:
  // Atomically deduct amountCents from prepaid balance after successful tool execution.
  // Store reason, request id, and timestamp for auditability.
}

// app/api/mcp-debug/route.ts
import { paymentRequiredResponse } from "@/lib/payment-required";
import { hasSufficientBalance, debitBalance } from "@/lib/balance";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DEBUG_SCAN_PRICE_CENTS = ${args.debugPriceCents};
const FIX_GENERATION_PRICE_CENTS = ${args.fixPriceCents};

export async function POST(req: Request) {
  const apiKey = req.headers.get("x-mcp-account") ?? req.headers.get("authorization");

  // CRITICAL:
  // Check payment BEFORE parsing or validating the request body.
  // This prevents MPP Scan warnings about missing WWW-Authenticate on 402.
  const paid = await hasSufficientBalance(apiKey, DEBUG_SCAN_PRICE_CENTS);

  if (!paid) {
    return paymentRequiredResponse({
      amountCents: DEBUG_SCAN_PRICE_CENTS,
      description: "Debug scan for MPP Scan and paid MCP/API endpoint warnings",
      toolName: "debug_mpp_scan_results"
    });
  }

  const body = await req.json();

  // Run scanner here.
  const result = {
    ok: true,
    message: "Run your diagnostic logic here.",
    input: body
  };

  await debitBalance(apiKey!, DEBUG_SCAN_PRICE_CENTS, "debug_mpp_scan_results");

  return Response.json(result);
}
`;
}

function generateExpress402Fix(args: {
  realm: string;
  method: string;
  debugPriceCents: number;
  fixPriceCents: number;
}) {
  return `// payment-required.ts
import crypto from "node:crypto";
import type { Request, Response, NextFunction } from "express";

export function paymentRequiredResponse(res: Response, options: {
  amountCents: number;
  description: string;
  toolName: string;
}) {
  const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  return res
    .status(402)
    .set("Content-Type", "application/json")
    .set("Cache-Control", "no-store")
    .set("WWW-Authenticate", 'Payment realm="${args.realm}", method="${args.method}"')
    .json({
      error: "payment_required",
      challenge: {
        id: crypto.randomUUID(),
        type: "${args.method}",
        amount: String(options.amountCents),
        currency: "USD",
        description: options.description,
        tool: options.toolName,
        expires,
        funding_url: "${args.realm.replace(/\/$/, "")}/fund"
      }
    });
}

async function hasSufficientBalance(apiKey: string | undefined, amountCents: number): Promise<boolean> {
  if (!apiKey) return false;

  // Production TODO:
  // Look up account by API key and verify prepaid balance.
  return false;
}

export function requirePayment(options: {
  amountCents: number;
  description: string;
  toolName: string;
}) {
  return async function paymentMiddleware(req: Request, res: Response, next: NextFunction) {
    const apiKey =
      req.header("x-mcp-account") ??
      req.header("authorization")?.replace(/^Bearer\\s+/i, "");

    // CRITICAL:
    // Mount this middleware BEFORE express.json() for paid routes when possible.
    // This ensures bad JSON does not produce 400 before the required 402 challenge.
    const paid = await hasSufficientBalance(apiKey, options.amountCents);

    if (!paid) {
      return paymentRequiredResponse(res, options);
    }

    return next();
  };
}

// server.ts
import express from "express";
import { requirePayment } from "./payment-required";

const app = express();

app.post(
  "/tools/debug_mpp_scan_results",
  requirePayment({
    amountCents: ${args.debugPriceCents},
    description: "Debug scan for MPP Scan and paid MCP/API endpoint warnings",
    toolName: "debug_mpp_scan_results"
  }),
  express.json(),
  async (req, res) => {
    res.json({
      ok: true,
      message: "Run diagnostic logic here.",
      input: req.body
    });
  }
);

app.post(
  "/tools/generate_mpp_fix",
  requirePayment({
    amountCents: ${args.fixPriceCents},
    description: "Generate production-ready fixes for MPP Scan warnings",
    toolName: "generate_mpp_fix"
  }),
  express.json(),
  async (req, res) => {
    res.json({
      ok: true,
      message: "Generate fix code here.",
      input: req.body
    });
  }
);

app.listen(process.env.PORT || 3000);
`;
}

const server = new McpServer({
  name: "mpp-compliance-doctor",
  version: "1.0.0"
});

server.tool(
  "debug_mpp_scan_results",
  `Diagnose MPP Scan failures from raw scanner output. 
Use this when an AI agent, Claude, OpenAI agent, Cursor, Replit, or developer sees errors like:
"Paid endpoint did not return payment options in the 402 response",
"WWW-Authenticate header contains no Payment challenges",
"Paid route has no price hint",
"Paid route does not declare supported payment protocols",
"Paid endpoint is missing an input schema",
"Fixed-price endpoint missing WWW-Authenticate header on 402",
"Payment challenge is missing id",
"Payment challenge is missing expires",
"Payment challenge is missing amount",
"Payment challenge is missing recipient",
or "Payment realm does not match origin host".

Returns categorized diagnostics, root causes, and prioritized fixes.`,
  {
    scan_output: z.string().min(1).describe("Raw MPP Scan output, warnings, errors, or logs.")
  },
  async ({ scan_output }) => {
    const lines = scan_output
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    const diagnostics = lines.map(classifyMppLine);
    const summary = summarizeDiagnostics(diagnostics);

    const priority_order = [
      "request_validation_order",
      "missing_www_authenticate",
      "missing_402_payment_options",
      "missing_challenge_id",
      "missing_challenge_expires",
      "missing_challenge_amount",
      "missing_challenge_recipient",
      "missing_input_schema",
      "missing_price_hint",
      "missing_protocols",
      "realm_origin_mismatch"
    ];

    const prioritized_fixes = priority_order
      .filter((category) => diagnostics.some((d) => d.category === category))
      .map((category) => {
        const sample = diagnostics.find((d) => d.category === category)!;
        return {
          category,
          count: diagnostics.filter((d) => d.category === category).length,
          root_cause: sample.root_cause,
          fix: sample.fix
        };
      });

    return textResponse({
      product: "MPP Compliance Doctor MCP",
      purpose:
        "Scan any MCP/API server output and explain exactly why MPP Scan is warning, then recommend the fix.",
      summary,
      prioritized_fixes,
      diagnostics,
      next_recommended_tool:
        "Call generate_nextjs_402_fix, generate_express_402_fix, scan_openapi_spec, or generate_openapi_payment_patch depending on the framework and failure category."
    });
  }
);

server.tool(
  "scan_openapi_spec",
  `Scan an OpenAPI JSON spec for MPP Scan and paid agent endpoint compatibility.
Checks paid MCP/API routes for missing x-payment-info.price, missing x-payment-info.protocols, missing requestBody or parameters schemas, and missing 402 Payment Required documentation.
Use this before submitting a paid MCP server to MPP Scan or when Claude/OpenAI agents cannot discover how to call or pay for tools.`,
  {
    openapi_json: z.string().min(1).describe("Complete OpenAPI JSON document as a string.")
  },
  async ({ openapi_json }) => {
    const parsed = safeJsonParse<OpenApiDocument>(openapi_json);

    if (!parsed.ok) {
      return textResponse({
        ok: false,
        error: "Invalid JSON",
        detail: parsed.error,
        fix: "Provide a valid OpenAPI JSON string. YAML is not supported by this tool yet."
      });
    }

    const diagnostics = scanOpenApiDocument(parsed.data);
    const summary = summarizeDiagnostics(diagnostics);

    return textResponse({
      ok: diagnostics.filter((d) => d.severity === "error").length === 0,
      summary,
      diagnostics,
      next_recommended_tool:
        "Call generate_openapi_payment_patch with the paid routes that need x-payment-info, 402 responses, or input schemas."
    });
  }
);

server.tool(
  "validate_402_response",
  `Validate a 402 Payment Required response for paid MCP/API endpoints.
Use this when MPP Scan says:
"Paid endpoint did not return payment options in the 402 response",
"WWW-Authenticate header contains no Payment challenges",
or "Fixed-price endpoint missing WWW-Authenticate header on 402".

Checks status, WWW-Authenticate Payment challenge, realm/origin match, challenge id, amount, expires, recipient, funding_url, and checkout_url.`,
  {
    status: z.number().optional().describe("HTTP status code returned by the endpoint."),
    headers_json: z
      .string()
      .optional()
      .describe("JSON object of response headers, for example {\"www-authenticate\":\"Payment realm=...\"}."),
    body_json: z
      .string()
      .optional()
      .describe("JSON response body returned by the endpoint."),
    origin: z
      .string()
      .url()
      .optional()
      .describe("Origin URL of the live service, used to validate realm host.")
  },
  async ({ status, headers_json, body_json, origin }) => {
    let headers: Record<string, string> = {};
    let body: any = {};

    if (headers_json) {
      const parsedHeaders = safeJsonParse<Record<string, string>>(headers_json);
      if (!parsedHeaders.ok) {
        return textResponse({
          ok: false,
          error: "Invalid headers_json",
          detail: parsedHeaders.error
        });
      }
      headers = parsedHeaders.data;
    }

    if (body_json) {
      const parsedBody = safeJsonParse(body_json);
      if (!parsedBody.ok) {
        return textResponse({
          ok: false,
          error: "Invalid body_json",
          detail: parsedBody.error
        });
      }
      body = parsedBody.data;
    }

    const diagnostics = validate402Response({ status, headers, body, origin });
    const summary = summarizeDiagnostics(diagnostics);

    return textResponse({
      ok: diagnostics.length === 0,
      summary,
      diagnostics,
      valid_402_template: {
        status: 402,
        headers: {
          "Content-Type": "application/json",
          "WWW-Authenticate":
            'Payment realm="https://your-domain.com", method="402"'
        },
        body: {
          error: "payment_required",
          challenge: {
            id: "challenge_unique_id",
            type: "402",
            amount: "75",
            currency: "USD",
            description: "Debug MCP server scan",
            expires: "2026-05-04T12:05:00Z",
            recipient: "merchant_or_payment_account",
            funding_url: "https://your-domain.com/fund"
          }
        }
      }
    });
  }
);

server.tool(
  "generate_openapi_payment_patch",
  `Generate an OpenAPI payment metadata patch for paid MCP/API endpoints.
Use this when MPP Scan says a paid route has no price hint, does not declare supported payment protocols, is missing an input schema, or does not document 402 Payment Required.
This generates x-payment-info.price, x-payment-info.protocols, requestBody/parameters, and 402 response documentation.`,
  {
    routes: z
      .array(z.string())
      .min(1)
      .describe("Routes to patch. Use format like 'POST /gpt/weather' or '/tools/debug_mpp_scan_results'."),
    price: z
      .string()
      .default("0.75")
      .describe("Price hint as a decimal string, for example '0.75' or '1.00'."),
    currency: z.string().default("USD").describe("Currency code."),
    protocols: z
      .array(z.string())
      .default(["402"])
      .describe("Supported payment protocols or challenge labels."),
    include_input_schema: z
      .boolean()
      .default(true)
      .describe("Whether to include generic input schemas in the patch.")
  },
  async ({ routes, price, currency, protocols, include_input_schema }) => {
    const patch = buildOpenApiPatch({
      routes,
      price,
      currency,
      protocols,
      includeInputSchema: include_input_schema
    });

    return textResponse(patch);
  }
);

server.tool(
  "generate_nextjs_402_fix",
  `Generate production-ready Next.js/Vercel code to fix MPP Scan 402 payment warnings.
Use this when a paid endpoint validates request body before payment, misses WWW-Authenticate, or returns an incomplete payment challenge.
The generated code checks payment before parsing JSON and returns a valid 402 Payment Required response.`,
  {
    realm: z
      .string()
      .url()
      .describe("Canonical origin of your service, for example https://mpp-compliance-doctor.vercel.app."),
    method: z
      .string()
      .default("402")
      .describe("Payment method/protocol label to put in WWW-Authenticate."),
    debug_price_cents: z
      .number()
      .int()
      .default(75)
      .describe("Debug scan price in cents."),
    fix_price_cents: z
      .number()
      .int()
      .default(100)
      .describe("Fix generation price in cents.")
  },
  async ({ realm, method, debug_price_cents, fix_price_cents }) => {
    return textResponse({
      files: {
        "lib/payment-required.ts and app/api/mcp-debug/route.ts": generateNextJs402Fix({
          realm,
          method,
          debugPriceCents: debug_price_cents,
          fixPriceCents: fix_price_cents
        })
      }
    });
  }
);

server.tool(
  "generate_express_402_fix",
  `Generate production-ready Express code to fix MPP Scan 402 payment warnings.
Use this when Express body parsing or validation returns 400 before a paid endpoint returns 402 Payment Required.
The generated middleware should be mounted before express.json() on paid routes.`,
  {
    realm: z
      .string()
      .url()
      .describe("Canonical origin of your service."),
    method: z
      .string()
      .default("402")
      .describe("Payment method/protocol label to put in WWW-Authenticate."),
    debug_price_cents: z
      .number()
      .int()
      .default(75)
      .describe("Debug scan price in cents."),
    fix_price_cents: z
      .number()
      .int()
      .default(100)
      .describe("Fix generation price in cents.")
  },
  async ({ realm, method, debug_price_cents, fix_price_cents }) => {
    return textResponse({
      files: {
        "payment-required.ts and server.ts": generateExpress402Fix({
          realm,
          method,
          debugPriceCents: debug_price_cents,
          fixPriceCents: fix_price_cents
        })
      }
    });
  }
);

server.tool(
  "explain_mpp_warning",
  `Explain one MPP Scan warning or error in plain English and return the exact fix.
Use this for single warnings like missing price hint, missing input schema, missing WWW-Authenticate, missing payment options, or protocol declaration problems.`,
  {
    warning: z.string().min(1).describe("One MPP Scan warning or error line.")
  },
  async ({ warning }) => {
    const diagnostic = classifyMppLine(warning);

    return textResponse({
      warning,
      diagnostic,
      exact_fix_order: [
        "Return 402 before parsing or validating request body.",
        "Add WWW-Authenticate with Payment challenge.",
        "Add a JSON challenge body with id, amount, currency, expires, and payment destination.",
        "Add OpenAPI x-payment-info.price and x-payment-info.protocols.",
        "Add requestBody or parameters schema so agents can call the endpoint."
      ]
    });
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("MPP Compliance Doctor MCP failed to start:", err);
  process.exit(1);
});
