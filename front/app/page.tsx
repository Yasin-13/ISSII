"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from "@/components/ui/accordion"
import { FaWindows, FaLinux, FaNetworkWired, FaCheckCircle, FaFilePdf, FaTimesCircle, FaHistory } from "react-icons/fa"

export default function SecurityAuditApp() {
  const [windowsAudit, setWindowsAudit] = useState<Record<string, any> | null>(null)
  const [linuxAudit, setLinuxAudit] = useState<Record<string, any> | null>(null)
  const [networkAudit, setNetworkAudit] = useState<Record<string, any> | null>(null)
  const [auditHistory, setAuditHistory] = useState<any[]>([])
  const [lastAuditTime, setLastAuditTime] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const fetchAuditHistory = async () => {
    try {
      const response = await fetch('http://localhost:5000/audit/history')
      const data = await response.json()
      setAuditHistory(data)
    } catch (error) {
      console.error('Error fetching audit history:', error)
    }
  }

  useEffect(() => {
    fetchAuditHistory()
  }, [])

  const performAudit = async (type: string) => {
    setLoading(true)
    try {
      const response = await fetch(`http://localhost:5000/audit/${type}`)
      const data = await response.json()
      
      if (type === "windows") setWindowsAudit(data)
      if (type === "linux") setLinuxAudit(data)
      if (type === "network") setNetworkAudit(data)

      // Update last audit time
      setLastAuditTime(new Date().toLocaleString())
      fetchAuditHistory() // Refresh audit history
    } catch (error) {
      console.error(`Error performing ${type} audit:`, error)
    } finally {
      setLoading(false)
    }
  }

  const generateReport = () => {
    window.open("http://localhost:5000/generate_report", "_blank")
  }

  const renderAuditSection = (title: string, auditData: Record<string, any> | null, icon: React.ReactNode) => (
    <div className="mb-6">
      <div className="flex items-center mb-2">
        <h2 className="text-2xl font-semibold mr-2">{title}</h2>
        {icon}
      </div>
      {auditData ? (
        <Accordion type="single" collapsible className="w-full">
          {Object.entries(auditData).map(([key, value]) => (
            <AccordionItem key={key} value={key}>
              <AccordionTrigger>
                {key}
                {value.passed ? (
                  <FaCheckCircle className="text-green-500 ml-2" />
                ) : (
                  <FaTimesCircle className="text-red-500 ml-2" />
                )}
              </AccordionTrigger>
              <AccordionContent>
                <pre className="whitespace-pre-wrap text-sm">{JSON.stringify(value.result, null, 2)}</pre>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      ) : (
        <p className="text-gray-500">No audit data available.</p>
      )}
    </div>
  )

  const renderAuditHistory = () => (
    <div className="mb-6">
      <div className="flex items-center mb-2">
        <h2 className="text-2xl font-semibold mr-2">Audit History</h2>
        <FaHistory />
      </div>
      {auditHistory.length > 0 ? (
        <Accordion type="single" collapsible className="w-full">
          {auditHistory.map((entry, index) => (
            <AccordionItem key={index} value={entry.timestamp}>
              <AccordionTrigger>{entry.timestamp}</AccordionTrigger>
              <AccordionContent>
                <pre className="whitespace-pre-wrap text-sm">{JSON.stringify(entry.results, null, 2)}</pre>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      ) : (
        <p className="text-gray-500">No audit history available.</p>
      )}
    </div>
  )

  useEffect(() => {
    // Fetch last audit time from local storage on component mount
    const storedLastAuditTime = localStorage.getItem("lastAuditTime")
    if (storedLastAuditTime) {
      setLastAuditTime(storedLastAuditTime)
    }
  }, [])

  useEffect(() => {
    // Store last audit time in local storage when it changes
    if (lastAuditTime) {
      localStorage.setItem("lastAuditTime", lastAuditTime)
    }
  }, [lastAuditTime])

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-4xl font-bold mb-4">Security Audit Dashboard</h1>
      <div className="flex space-x-4 mb-4">
        <Button onClick={() => performAudit("windows")} disabled={loading} className="flex items-center space-x-2">
          <FaWindows />
          <span>{loading ? "Auditing..." : "Audit Windows"}</span>
        </Button>
        <Button onClick={() => performAudit("linux")} disabled={loading} className="flex items-center space-x-2">
          <FaLinux />
          <span>{loading ? "Auditing..." : "Audit Linux"}</span>
        </Button>
        <Button onClick={() => performAudit("network")} disabled={loading} className="flex items-center space-x-2">
          <FaNetworkWired />
          <span>{loading ? "Auditing..." : "Audit Network Infra"}</span>
        </Button>
        <Button onClick={generateReport} disabled={!windowsAudit && !linuxAudit && !networkAudit} className="flex items-center space-x-2">
          <FaFilePdf />
          <span>Generate PDF Report</span>
        </Button>
      </div>
      {lastAuditTime && <p className="text-gray-500 mb-4">Last Audit Performed: {lastAuditTime}</p>}
      {renderAuditSection("Windows Audit", windowsAudit, <FaWindows />)}
      {renderAuditSection("Linux Audit", linuxAudit, <FaLinux />)}
      {renderAuditSection("Network Infrastructure Audit", networkAudit, <FaNetworkWired />)}
      {renderAuditHistory()}
    </div>
  )
}