import { Actor } from "apify";
import { callApi } from "../shared/client";

interface Input {
  url: string;
}

await Actor.init();

const input = await Actor.getInput<Input>();
if (!input?.url) {
  throw new Error("Missing required input: url");
}

const result = await callApi("tech-stack", "/check", { url: input.url });

await Actor.charge({ eventName: "check", count: 1 });
await Actor.pushData(result);

await Actor.exit();
