import { NextRequest, NextResponse } from "next/server";

/**
 * Allowed origins for CORS requests.
 * In production, this should be set via the ALLOWED_ORIGINS environment variable
 * as a comma-separated list of allowed origins.
 * If not set, only same-origin requests are allowed.
 */
function getAllowedOrigins(): string[] {
  const envOrigins = process.env.ALLOWED_ORIGINS;
  if (envOrigins) {
    return envOrigins.split(",").map((o) => o.trim());
  }
  return [];
}

function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) {
    // No origin header means same-origin request (non-browser or same-origin)
    return true;
  }

  const allowedOrigins = getAllowedOrigins();

  // If no allowed origins are configured, reject all cross-origin requests
  if (allowedOrigins.length === 0) {
    return false;
  }

  return allowedOrigins.includes(origin);
}

export function middleware(request: NextRequest) {
  const origin = request.headers.get("origin");
  const isApiRoute = request.nextUrl.pathname.startsWith("/api/");

  // Only apply CORS handling to API routes
  if (!isApiRoute) {
    return NextResponse.next();
  }

  // Handle CORS preflight (OPTIONS) requests
  if (request.method === "OPTIONS") {
    const response = new NextResponse(null, { status: 204 });

    if (origin && isAllowedOrigin(origin)) {
      response.headers.set("Access-Control-Allow-Origin", origin);
      response.headers.set("Access-Control-Allow-Credentials", "true");
      response.headers.set(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS"
      );
      response.headers.set(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization"
      );
      response.headers.set("Access-Control-Max-Age", "86400");
    }
    // If origin is not allowed, return preflight response without CORS headers
    // which will cause the browser to block the request
    return response;
  }

  // For actual requests, proceed but set appropriate CORS headers
  const response = NextResponse.next();

  if (origin && isAllowedOrigin(origin)) {
    response.headers.set("Access-Control-Allow-Origin", origin);
    response.headers.set("Access-Control-Allow-Credentials", "true");
  }
  // If origin is not allowed and is present (cross-origin request),
  // do NOT set any Access-Control-Allow-Origin header.
  // The browser will block the response from being read by the attacker's script.

  return response;
}

export const config = {
  matcher: ["/api/:path*"],
};
