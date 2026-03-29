const BASE_DOMAIN = (process.env.APIMESH_BASE_URL || "https://apimesh.xyz").replace("https://", "").replace("http://", "");
const API_KEY = process.env.APIMESH_ACTOR_KEY;

export async function callApi(subdomain: string, path: string, params: Record<string, string>): Promise<any> {
  if (!API_KEY) throw new Error("APIMESH_ACTOR_KEY not set");

  const url = new URL(path, `https://${subdomain}.${BASE_DOMAIN}`);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  const res = await fetch(url.toString(), {
    headers: { "Authorization": `Bearer ${API_KEY}` },
  });

  if (!res.ok) {
    throw new Error(`API returned ${res.status}: ${await res.text()}`);
  }

  return res.json();
}
