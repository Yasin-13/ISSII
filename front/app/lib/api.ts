export async function fetchAuditData() {
  const response = await fetch("http://localhost:5000/audit", { cache: "no-store" })
  if (!response.ok) {
    throw new Error("Failed to fetch audit data")
  }
  return response.json()
}

