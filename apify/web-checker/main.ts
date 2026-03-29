import { Actor } from "apify";
import { callApi } from "../shared/client";

interface Input {
  name: string;
}

await Actor.init();

const input = await Actor.getInput<Input>();
if (!input?.name) {
  throw new Error("Missing required input: name (brand/product name to check)");
}

const result = await callApi("check", "/check", { name: input.name });

await Actor.charge({ eventName: "check", count: 1 });
await Actor.pushData(result);

await Actor.exit();
