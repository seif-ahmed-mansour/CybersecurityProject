import type { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

export function sha1Library(data: string | Buffer): string {
  return createHash("sha1").update(data).digest("hex");
}
