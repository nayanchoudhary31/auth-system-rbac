import type { Request, Response, NextFunction } from "express";
import { AppError } from "../utils/errors.js";

export function globalErrorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction,
) {
  console.error("Global error handler:", err);

  // Normalize error
  const isAppError = err instanceof AppError;
  const statusCode = isAppError ? err.statusCode : 500;
  const message =
    isAppError && err.message
      ? err.message
      : "Something went wrong. Please try again.";

  // Optionally add more detail in development
  const response: any = { error: message };
  if (process.env.NODE_ENV !== "production" && err instanceof Error) {
    response.details = err.stack;
  }

  res.status(statusCode).json(response);
}
