#!/usr/bin/env node

// Oracle Server Template

import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import { createHash } from 'crypto';

// Basic types
interface ForeignCallInfo {
  function: string;
  inputs: string[][];
}

interface ForeignCallResult {
  values: string[][];
}

// Express app setup
const app = express();
app.use(cors());
app.use(bodyParser.json());

// Main endpoint
app.post("/", async (req, res) => {
  const { method, params, id } = req.body;
  
  if (method === "resolve_foreign_call") {
    const result = await handleForeignCall(params || []);
    res.json({ jsonrpc: "2.0", id, result });
  } else {
    res.json({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } });
  }
});

async function handleForeignCall(params: any[]): Promise<ForeignCallResult> {
  const [callInfo] = params as [ForeignCallInfo];
  const { function: functionName, inputs } = callInfo;


  if (functionName === "getSHA512") {
    return sha512_hash(inputs);
  } else if (functionName === "getSHA384") {
    return sha384_hash(inputs);
  } else {
    throw new Error(`Unknown function: ${functionName}`);
  }
}

function sha512_hash(inputs: any): ForeignCallResult {
  // Input format: BoundedVec is passed as a struct with two fields:
  // inputs[0] = storage array (all possible bytes as hex strings)
  // inputs[1] = len (actual length as hex string)

  const storageArray = inputs[0] as string[];
  const lenHex = inputs[1] as string;
  var len = parseInt(lenHex, 16);

  len = len % (storageArray.length + 1);

  // Only use the first 'len' bytes from storage
  const bytes = Uint8Array.from(
    storageArray.slice(0, len).map(h => parseInt(h, 16))
  );

  const hashResultBytes: string[] =
    Array.from(createHash('sha512').update(bytes).digest())
      .map(b => '0x' + b.toString(16).padStart(2, '0'));

  return { values: [hashResultBytes] };
}

function sha384_hash(inputs: any): ForeignCallResult {
  // Input format: BoundedVec is passed as a struct with two fields:
  // inputs[0] = storage array (all possible bytes as hex strings)
  // inputs[1] = len (actual length as hex string)

  const storageArray = inputs[0] as string[];
  const lenHex = inputs[1] as string;
  var len = parseInt(lenHex, 16);

  len = len % (storageArray.length + 1);

  // Only use the first 'len' bytes from storage
  const bytes = Uint8Array.from(
    storageArray.slice(0, len).map(h => parseInt(h, 16))
  );

  // SHA384 produces 48 bytes (384 bits), but we need to return only the first 48 bytes
  const hashResultBytes: string[] =
    Array.from(createHash('sha384').update(bytes).digest())
      .map(b => '0x' + b.toString(16).padStart(2, '0'));

  return { values: [hashResultBytes] };
}

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Start server
const PORT = process.env.PORT || 8095;
app.listen(PORT, () => {
  console.log(`Oracle server running on port ${PORT}`);
});
