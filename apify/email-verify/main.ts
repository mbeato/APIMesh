import { Actor } from "apify";
import { callApi } from "../shared/client";

interface Input {
  email: string;
}

await Actor.init();

const input = await Actor.getInput<Input>();
if (!input?.email) {
  throw new Error("Missing required input: email");
}

const result = await callApi("email-verify", "/check", { email: input.email });

await Actor.charge({ eventName: "check", count: 1 });
await Actor.pushData(result);

await Actor.exit();
