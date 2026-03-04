exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  const apiBase = process.env.API_BASE_URL;
  if (!apiBase) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Missing API_BASE_URL env var" }),
    };
  }

  try {
    const res = await fetch(`${apiBase}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: event.body || "{}",
    });

    const text = await res.text();
    return {
      statusCode: res.status,
      headers: { "Content-Type": "application/json" },
      body: text,
    };
  } catch (e) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Proxy error" }),
    };
  }
};