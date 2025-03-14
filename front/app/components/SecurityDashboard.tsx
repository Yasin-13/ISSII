import { Suspense } from "react"
import { fetchAuditData } from "../lib/api"
import SecurityCheck from "./SecurityCheck"
import GenerateReportButton from "./GenerateReportButton"
import Loading from "../loading"
import SecuritySection from "./SecuritySection" // Import the missing component

export default async function SecurityDashboard() {
  const auditData = await fetchAuditData()

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <SecurityCheck title="Firewall" status={auditData["Firewall Check"]} />
        <SecurityCheck title="Windows Defender" status={auditData["Defender Check"]} />
        <SecurityCheck title="Automatic Updates" status={auditData["Automatic Updates Check"]} />
        <SecurityCheck title="User Account Control (UAC)" status={auditData["UAC Check"]} />
        <SecurityCheck title="Guest Account" status={auditData["Guest Account Check"]} />
        <SecurityCheck title="BitLocker" status={auditData["BitLocker Status"]} />
      </div>

      <SecuritySection title="System Information" data={auditData["System Information"]} />
      <SecuritySection title="Shared Folders" data={auditData["Shared Folders"]} />
      <SecuritySection title="User Accounts" data={auditData["User Accounts"]} />
      <SecuritySection title="Installed Antivirus" data={auditData["Installed Antivirus"]} />
      <SecuritySection title="Running Services" data={auditData["Running Services"]} />
      <SecuritySection title="Audit Policy" data={auditData["Audit Policy"]} />
      <SecuritySection title="Listening Ports" data={auditData["Listening Ports"]} />
      <SecuritySection title="Admin Users" data={auditData["Admin Users"]} />

      <Suspense fallback={<Loading />}>
        <GenerateReportButton />
      </Suspense>
    </div>
  )
}

