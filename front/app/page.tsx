"use client"

import type React from "react"

import { useState, useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from "@/components/ui/accordion"
import {
  FaWindows,
  FaLinux,
  FaNetworkWired,
  FaCheckCircle,
  FaFilePdf,
  FaTimesCircle,
  FaHistory,
  FaServer,
  FaShieldAlt,
  FaExclamationTriangle,
  FaInfoCircle,
  FaSync,
  FaFilter,
  FaFileDownload,
  FaChartLine,
  FaFileAlt,
  FaFileUpload,
  FaRobot,
  FaStop,
  FaPlay,
} from "react-icons/fa"

export default function SecurityAuditApp() {
  const [windowsAudit, setWindowsAudit] = useState<Record<string, any> | null>(null)
  const [linuxAudit, setLinuxAudit] = useState<Record<string, any> | null>(null)
  const [networkAudit, setNetworkAudit] = useState<Record<string, any> | null>(null)
  const [webserverAudit, setWebserverAudit] = useState<Record<string, any> | null>(null)
  const [auditHistory, setAuditHistory] = useState<any[]>([])
  const [lastAuditTime, setLastAuditTime] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState("results")
  const [severityFilter, setSeverityFilter] = useState("all")
  const [statusFilter, setStatusFilter] = useState("all")
  const [networkTrafficAudit, setNetworkTrafficAudit] = useState<Record<string, any> | null>(null)
  const [predictiveAnalysis, setPredictiveAnalysis] = useState<Record<string, any> | null>(null)
  const [generatingReport, setGeneratingReport] = useState<Record<string, boolean>>({
    windows: false,
    linux: false,
    network: false,
    webserver: false,
    all: false,
  })

  const [networkTrafficMode, setNetworkTrafficMode] = useState<"realtime" | "upload" | "ml-analysis">("realtime")
  const [networkTrafficFile, setNetworkTrafficFile] = useState<File | null>(null)
  const [isProcessingUpload, setIsProcessingUpload] = useState(false)

  // ML-based traffic analysis states
  const [mlPackets, setMlPackets] = useState<any[]>([])
  const [isCapturing, setIsCapturing] = useState(false)
  const [captureStats, setCaptureStats] = useState({
    total: 0,
    normal: 0,
    intrusion: 0,
  })
  const captureIntervalRef = useRef<NodeJS.Timeout | null>(null)

  // Calculate security scores
  const calculateScore = (auditData: Record<string, any> | null): number => {
    if (!auditData) return 0
    const total = Object.keys(auditData).length
    if (total === 0) return 0

    const passed = Object.values(auditData).filter((item) => item.passed).length
    return Math.round((passed / total) * 100)
  }

  const windowsScore = calculateScore(windowsAudit)
  const linuxScore = calculateScore(linuxAudit)
  const networkScore = calculateScore(networkAudit)
  const webserverScore = calculateScore(webserverAudit)
  const networkTrafficScore = calculateScore(networkTrafficAudit)
  const predictiveScore = calculateScore(predictiveAnalysis)

  const overallScore = Math.round(
    (windowsScore + linuxScore + networkScore + webserverScore + networkTrafficScore + predictiveScore) /
      ((windowsAudit ? 1 : 0) +
        (linuxAudit ? 1 : 0) +
        (networkAudit ? 1 : 0) +
        (webserverAudit ? 1 : 0) +
        (networkTrafficAudit ? 1 : 0) +
        (predictiveAnalysis ? 1 : 0) || 1),
  )

  const fetchAuditHistory = async () => {
    try {
      const response = await fetch("http://localhost:5000/audit/history")
      const data = await response.json()
      setAuditHistory(data)
    } catch (error) {
      console.error("Error fetching audit history:", error)
    }
  }

  useEffect(() => {
    fetchAuditHistory()

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

  // Cleanup interval on unmount
  useEffect(() => {
    return () => {
      if (captureIntervalRef.current) {
        clearInterval(captureIntervalRef.current)
      }
    }
  }, [])

  const performAudit = async (type: string) => {
    setLoading(true)
    try {
      const response = await fetch(`http://localhost:5000/audit/${type}`)
      const data = await response.json()

      // Enhance the data with severity levels for failed checks
      const enhancedData: Record<string, any> = {}
      Object.entries(data).forEach(([key, value]: [string, any]) => {
        enhancedData[key] = {
          ...value,
          severity: value.passed ? "low" : ["critical", "high", "medium", "low"][Math.floor(Math.random() * 4)],
          remediation: value.passed
            ? ""
            : `Recommended action for ${key}: Update configurations according to security policy.`,
        }
      })

      if (type === "windows") setWindowsAudit(enhancedData)
      if (type === "linux") setLinuxAudit(enhancedData)
      if (type === "router") setNetworkAudit(enhancedData)
      if (type === "webserver") setWebserverAudit(enhancedData)

      // Update last audit time
      const currentTime = new Date().toLocaleString()
      setLastAuditTime(currentTime)
      fetchAuditHistory() // Refresh audit history
    } catch (error) {
      console.error(`Error performing ${type} audit:`, error)
    } finally {
      setLoading(false)
    }
  }

  const generateIndividualReport = async (type: string) => {
    setGeneratingReport((prev) => ({ ...prev, [type]: true }))
    try {
      // Use the backend's individual report generation endpoint
      window.open(`http://localhost:5000/generate_report/${type}`, "_blank")
    } catch (error) {
      console.error(`Error generating ${type} report:`, error)
    } finally {
      setTimeout(() => {
        setGeneratingReport((prev) => ({ ...prev, [type]: false }))
      }, 2000)
    }
  }

  const generateReport = () => {
    setGeneratingReport((prev) => ({ ...prev, all: true }))
    try {
      // Generate reports for all available audit types
      if (windowsAudit) generateIndividualReport("windows")
      if (linuxAudit) generateIndividualReport("linux")
      if (networkAudit) generateIndividualReport("router")
      if (webserverAudit) generateIndividualReport("webserver")
    } catch (error) {
      console.error("Error generating reports:", error)
    } finally {
      setTimeout(() => {
        setGeneratingReport((prev) => ({ ...prev, all: false }))
      }, 2000)
    }
  }

  const fetchNetworkTraffic = async () => {
    try {
      setLoading(true)
      // Simulate API call
      setTimeout(() => {
        const mockData = {
          "Unusual Port Access": {
            passed: false,
            result: {
              details: "Detected unusual access on ports 4444, 5555",
              timestamp: new Date().toISOString(),
              source_ips: ["192.168.1.45", "10.0.0.12"],
            },
            severity: "high",
            remediation: "Block access to unused ports and investigate source IPs for potential compromise.",
          },
          "Traffic Spikes": {
            passed: true,
            result: {
              details: "No abnormal traffic spikes detected in the last 24 hours",
              peak_traffic: "2.3 GB/s at 14:30",
              average: "1.1 GB/s",
            },
            severity: "low",
          },
          "Data Exfiltration": {
            passed: false,
            result: {
              details: "Potential data exfiltration detected",
              destination: "185.92.xx.xx",
              data_volume: "1.2 GB",
              timestamp: new Date().toISOString(),
            },
            severity: "critical",
            remediation: "Immediately block the destination IP and investigate the affected systems.",
          },
          "Protocol Anomalies": {
            passed: true,
            result: {
              details: "No protocol anomalies detected",
              protocols_analyzed: ["HTTP", "HTTPS", "DNS", "SMTP"],
            },
            severity: "low",
          },
          "Suspicious Connections": {
            passed: false,
            result: {
              details: "Connections to known malicious hosts detected",
              count: 3,
              destinations: ["malicious-domain1.com", "malicious-domain2.com"],
            },
            severity: "high",
            remediation: "Update firewall rules to block these domains and scan affected systems for malware.",
          },
        }
        setNetworkTrafficAudit(mockData)
        setLoading(false)
      }, 1500)
    } catch (error) {
      console.error("Error fetching network traffic data:", error)
      setLoading(false)
    }
  }

  const fetchPredictiveAnalysis = async () => {
    try {
        setLoading(true);
        // Simulate API call
        setTimeout(() => {
            const mockData = {
                "Windows Audit": {
                    passed: true,
                    result: {
                        system_info: {
                            pc_name: "mohamed yasin",
                            ip_address: "192.168.1.100",
                            os_version: "Microsoft Windows 10"
                        },
                        firewall_status: "Enabled",
                        windows_defender: "Enabled",
                        automatic_updates: "Enabled",
                        uac_status: "Enabled",
                        guest_account_status: "Disabled",
                        shared_folders: ["SharedFolder1", "SharedFolder2"],
                        listening_ports: [
                            "0.0.0.0:80",
                            "0.0.0.0:443"
                        ],
                        audit_policies: [
                            "System audit policy",
                            "Logon audit policy"
                        ],
                        running_processes: [
                            { name: "chrome", id: 1234 },
                            { name: "explorer", id: 5678 }
                        ],
                        disk_encryption_status: ["FullyEncrypted"],
                        installed_programs: [
                            { name: "Google Chrome", version: "89.0.4389.82" },
                            { name: "Microsoft Office", version: "16.0.12325.20288" }
                        ]
                    }
                },
                "Linux Audit": {
                    passed: true,
                    result: {
                        os_version: "Ubuntu 20.04.1 LTS",
                        kernel_version: "5.4.0-66-generic",
                        firewall_status: "active",
                        running_services: [
                            "accounts-daemon.service: running",
                            "acpid.service: running"
                        ],
                        listening_ports: [
                            "0.0.0.0:22"
                        ],
                        users: ["root", "user1"],
                        groups: ["root", "sudo"],
                        installed_packages: ["acl", "adduser", "apache2"],
                        scheduled_cron_jobs: [
                            "0 5 * * * /usr/bin/backup"
                        ],
                        disk_usage: [
                            "/dev/sda1 50G 20G 28G 42% /"
                        ],
                        memory_usage: [
                            "7972MB total, 1719MB used, 6252MB free"
                        ],
                        cpu_usage: [
                            "1.3% user, 0.7% system, 97.6% idle"
                        ],
                        log_files: [
                            "Mar 27 15:34:56: Starting Daily apt download activities...",
                            "Mar 27 15:34:56: Started Daily apt download activities."
                        ]
                    }
                }
            };
            setPredictiveAnalysis(mockData);
            setLoading(false);
        }, 1500);
    } catch (error) {
        console.error("Error fetching predictive analysis:", error);
        setLoading(false);
    }
}

  // Fetch ML-based packet analysis data
  const fetchMlPackets = async () => {
    try {
      const response = await fetch("http://localhost:5000/get_packets")
      const data = await response.json()

      // Update statistics
      const normalCount = data.filter((packet: any) => packet.prediction === "Normal").length
      const intrusionCount = data.filter((packet: any) => packet.prediction === "Intrusion").length

      setCaptureStats((prev) => ({
        total: prev.total + data.length,
        normal: prev.normal + normalCount,
        intrusion: prev.intrusion + intrusionCount,
      }))

      // Add new packets to the beginning of the array (most recent first)
      setMlPackets((prev) => [...data, ...prev].slice(0, 100))
    } catch (error) {
      console.error("Error fetching ML packet data:", error)
    }
  }

  const startMlCapture = () => {
    setIsCapturing(true)
    // Reset stats when starting a new capture
    setCaptureStats({
      total: 0,
      normal: 0,
      intrusion: 0,
    })

    // Start polling for packet data
    captureIntervalRef.current = setInterval(fetchMlPackets, 2000)
  }

  const stopMlCapture = () => {
    setIsCapturing(false)
    if (captureIntervalRef.current) {
      clearInterval(captureIntervalRef.current)
      captureIntervalRef.current = null
    }
  }

  useEffect(() => {
    fetchNetworkTraffic()
    fetchPredictiveAnalysis()
  }, [])

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return <FaExclamationTriangle className="text-red-500" />
      case "high":
        return <FaExclamationTriangle className="text-orange-500" />
      case "medium":
        return <FaExclamationTriangle className="text-yellow-500" />
      case "low":
        return <FaInfoCircle className="text-blue-500" />
      default:
        return <FaInfoCircle className="text-blue-500" />
    }
  }

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case "critical":
        return "text-red-500 bg-red-100 border border-red-200 px-2 py-0.5 rounded text-xs font-medium"
      case "high":
        return "text-orange-500 bg-orange-100 border border-orange-200 px-2 py-0.5 rounded text-xs font-medium"
      case "medium":
        return "text-yellow-600 bg-yellow-100 border border-yellow-200 px-2 py-0.5 rounded text-xs font-medium"
      case "low":
        return "text-green-600 bg-green-100 border border-green-200 px-2 py-0.5 rounded text-xs font-medium"
      default:
        return "text-blue-600 bg-blue-100 border border-blue-200 px-2 py-0.5 rounded text-xs font-medium"
    }
  }

  const getScoreColorClass = (score: number) => {
    if (score >= 90) return "text-green-600"
    if (score >= 70) return "text-yellow-600"
    if (score >= 50) return "text-orange-600"
    return "text-red-600"
  }

  const filterAuditData = (auditData: Record<string, any> | null) => {
    if (!auditData) return {}

    return Object.entries(auditData).reduce(
      (filtered, [key, value]) => {
        const severityMatch = severityFilter === "all" || value.severity === severityFilter
        const statusMatch =
          statusFilter === "all" ||
          (statusFilter === "passed" && value.passed) ||
          (statusFilter === "failed" && !value.passed)

        if (severityMatch && statusMatch) {
          filtered[key] = value
        }
        return filtered
      },
      {} as Record<string, any>,
    )
  }

  const renderAuditSection = (
    title: string,
    auditData: Record<string, any> | null,
    icon: React.ReactNode,
    score: number,
    auditType: string,
  ) => {
    const filteredData = filterAuditData(auditData)

    return (
      <div className="mb-6 border rounded-lg shadow-sm p-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <div className="mr-2 text-xl">{icon}</div>
            <div>
              <h2 className="text-2xl font-semibold">{title}</h2>
              <p className="text-gray-500 text-sm">
                {auditData ? `${Object.keys(auditData).length} checks performed` : "No audit data available"}
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <div className="text-right">
              <div className={`text-2xl font-bold ${getScoreColorClass(score)}`}>{score}%</div>
              <p className="text-gray-500 text-sm">Security Score</p>
            </div>
            {auditData && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => generateIndividualReport(auditType)}
                disabled={generatingReport[auditType]}
                className="ml-2"
              >
                {generatingReport[auditType] ? (
                  <FaSync className="animate-spin mr-2" />
                ) : (
                  <FaFileDownload className="mr-2" />
                )}
                {generatingReport[auditType] ? "Generating..." : "PDF Report"}
              </Button>
            )}
          </div>
        </div>

        <div className="w-full bg-gray-200 rounded-full h-2.5 mb-4">
          <div
            className={`h-2.5 rounded-full ${
              score >= 90
                ? "bg-green-500"
                : score >= 70
                  ? "bg-yellow-500"
                  : score >= 50
                    ? "bg-orange-500"
                    : "bg-red-500"
            }`}
            style={{ width: `${score}%` }}
          ></div>
        </div>

        {auditData ? (
          Object.keys(filteredData).length > 0 ? (
            <Accordion type="single" collapsible className="w-full">
              {Object.entries(filteredData).map(([key, value]) => (
                <AccordionItem key={key} value={key}>
                  <AccordionTrigger>
                    <div className="flex items-center justify-between w-full pr-4">
                      <div className="flex items-center">
                        {value.passed ? (
                          <FaCheckCircle className="text-green-500 mr-2" />
                        ) : (
                          <FaTimesCircle className="text-red-500 mr-2" />
                        )}
                        <span>{key}</span>
                      </div>
                      {!value.passed && value.severity && (
                        <span className={`ml-2 ${getSeverityClass(value.severity)}`}>
                          {value.severity.toUpperCase()}
                        </span>
                      )}
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="p-4 rounded-md bg-gray-50">
                      <pre className="whitespace-pre-wrap text-sm mb-2">{JSON.stringify(value.result, null, 2)}</pre>

                      {!value.passed && value.remediation && (
                        <div className="mt-4 p-3 border-l-4 border-blue-500 bg-blue-50">
                          <div className="flex items-start">
                            <FaInfoCircle className="text-blue-500 mr-2 mt-0.5" />
                            <div>
                              <h4 className="font-medium text-blue-700">Remediation</h4>
                              <p className="text-sm text-blue-600">{value.remediation}</p>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          ) : (
            <p className="text-gray-500">No results match the current filters.</p>
          )
        ) : (
          <div className="flex flex-col items-center justify-center py-8">
            <FaShieldAlt className="text-gray-400 text-4xl mb-2" />
            <p className="text-gray-500">Run an audit to see results</p>
          </div>
        )}
      </div>
    )
  }

  const renderAuditHistory = () => (
    <div className="mb-6 border rounded-lg shadow-sm p-4">
      <div className="flex items-center mb-4">
        <FaHistory className="mr-2 text-xl" />
        <h2 className="text-2xl font-semibold">Audit History</h2>
      </div>
      {auditHistory.length > 0 ? (
        <Accordion type="single" collapsible className="w-full">
          {auditHistory.map((entry, index) => (
            <AccordionItem key={index} value={entry.timestamp}>
              <AccordionTrigger>
                <div className="flex items-center justify-between w-full pr-4">
                  <span>{entry.timestamp}</span>
                  <span
                    className={`ml-2 px-2 py-0.5 rounded text-xs font-medium ${
                      entry.overallScore >= 90
                        ? "bg-green-100 text-green-600"
                        : entry.overallScore >= 70
                          ? "bg-yellow-100 text-yellow-600"
                          : entry.overallScore >= 50
                            ? "bg-orange-100 text-orange-600"
                            : "bg-red-100 text-red-600"
                    }`}
                  >
                    Score: {entry.overallScore}%
                  </span>
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="p-4 rounded-md bg-gray-50">
                  <h4 className="font-medium mb-2">Audit Type: {entry.type}</h4>
                  <pre className="whitespace-pre-wrap text-sm">{JSON.stringify(entry.results, null, 2)}</pre>
                </div>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      ) : (
        <div className="flex flex-col items-center justify-center py-8">
          <FaHistory className="text-gray-400 text-4xl mb-2" />
          <p className="text-gray-500">No audit history available</p>
        </div>
      )}
    </div>
  )

  const renderDashboard = () => (
    <>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="border rounded-lg shadow-sm p-4">
          <h3 className="text-sm font-medium text-gray-500 mb-1">Overall Security Score</h3>
          <div className="flex items-center justify-between">
            <div className={`text-3xl font-bold ${getScoreColorClass(overallScore)}`}>{overallScore}%</div>
            <FaShieldAlt
              className={`text-2xl ${
                overallScore >= 80 ? "text-green-500" : overallScore >= 50 ? "text-yellow-500" : "text-red-500"
              }`}
            />
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5 mt-2">
            <div
              className={`h-2.5 rounded-full ${
                overallScore >= 90
                  ? "bg-green-500"
                  : overallScore >= 70
                    ? "bg-yellow-500"
                    : overallScore >= 50
                      ? "bg-orange-500"
                      : "bg-red-500"
              }`}
              style={{ width: `${overallScore}%` }}
            ></div>
          </div>
        </div>

        <div className="border rounded-lg shadow-sm p-4">
          <h3 className="text-sm font-medium text-gray-500 mb-1">Windows Security</h3>
          <div className="flex items-center justify-between">
            <div className={`text-3xl font-bold ${getScoreColorClass(windowsScore)}`}>{windowsScore}%</div>
            <FaWindows className="text-2xl text-blue-500" />
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5 mt-2">
            <div
              className={`h-2.5 rounded-full ${
                windowsScore >= 90
                  ? "bg-green-500"
                  : windowsScore >= 70
                    ? "bg-yellow-500"
                    : windowsScore >= 50
                      ? "bg-orange-500"
                      : "bg-red-500"
              }`}
              style={{ width: `${windowsScore}%` }}
            ></div>
          </div>
        </div>

        <div className="border rounded-lg shadow-sm p-4">
          <h3 className="text-sm font-medium text-gray-500 mb-1">Linux Security</h3>
          <div className="flex items-center justify-between">
            <div className={`text-3xl font-bold ${getScoreColorClass(linuxScore)}`}>{linuxScore}%</div>
            <FaLinux className="text-2xl text-orange-500" />
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5 mt-2">
            <div
              className={`h-2.5 rounded-full ${
                linuxScore >= 90
                  ? "bg-green-500"
                  : linuxScore >= 70
                    ? "bg-yellow-500"
                    : linuxScore >= 50
                      ? "bg-orange-500"
                      : "bg-red-500"
              }`}
              style={{ width: `${linuxScore}%` }}
            ></div>
          </div>
        </div>

        <div className="border rounded-lg shadow-sm p-4">
          <h3 className="text-sm font-medium text-gray-500 mb-1">Network Security</h3>
          <div className="flex items-center justify-between">
            <div className={`text-3xl font-bold ${getScoreColorClass(networkScore)}`}>{networkScore}%</div>
            <FaNetworkWired className="text-2xl text-purple-500" />
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5 mt-2">
            <div
              className={`h-2.5 rounded-full ${
                networkScore >= 90
                  ? "bg-green-500"
                  : networkScore >= 70
                    ? "bg-yellow-500"
                    : networkScore >= 50
                      ? "bg-orange-500"
                      : "bg-red-500"
              }`}
              style={{ width: `${networkScore}%` }}
            ></div>
          </div>
        </div>
        <div className="border rounded-lg shadow-sm p-4">
          <h3 className="text-sm font-medium text-gray-500 mb-1">Network Traffic Security</h3>
          <div className="flex items-center justify-between">
            <div className={`text-3xl font-bold ${getScoreColorClass(networkTrafficScore)}`}>
              {networkTrafficScore}%
            </div>
            <FaNetworkWired className="text-2xl text-blue-500" />
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5 mt-2">
            <div
              className={`h-2.5 rounded-full ${
                networkTrafficScore >= 90
                  ? "bg-green-500"
                  : networkTrafficScore >= 70
                    ? "bg-yellow-500"
                    : networkTrafficScore >= 50
                      ? "bg-orange-500"
                      : "bg-red-500"
              }`}
              style={{ width: `${networkTrafficScore}%` }}
            ></div>
          </div>
        </div>

        <div className="border rounded-lg shadow-sm p-4">
          <h3 className="text-sm font-medium text-gray-500 mb-1">Predictive Security</h3>
          <div className="flex items-center justify-between">
            <div className={`text-3xl font-bold ${getScoreColorClass(predictiveScore)}`}>{predictiveScore}%</div>
            <FaShieldAlt className="text-2xl text-purple-500" />
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5 mt-2">
            <div
              className={`h-2.5 rounded-full ${
                predictiveScore >= 90
                  ? "bg-green-500"
                  : predictiveScore >= 70
                    ? "bg-yellow-500"
                    : predictiveScore >= 50
                      ? "bg-orange-500"
                      : "bg-red-500"
              }`}
              style={{ width: `${predictiveScore}%` }}
            ></div>
          </div>
        </div>
      </div>

      <div className="mb-6 border rounded-lg shadow-sm p-4">
        <div className="flex items-center mb-4">
          <FaExclamationTriangle className="text-red-500 mr-2 text-xl" />
          <h2 className="text-2xl font-semibold">Critical Issues</h2>
        </div>
        {[windowsAudit, linuxAudit, networkAudit, webserverAudit].some(
          (audit) => audit && Object.values(audit).some((item) => !item.passed && item.severity === "critical"),
        ) ? (
          <div className="space-y-4">
            {windowsAudit &&
              Object.entries(windowsAudit)
                .filter(([_, value]) => !value.passed && value.severity === "critical")
                .map(([key, value]) => (
                  <div key={`windows-${key}`} className="p-4 border border-red-200 rounded-md bg-red-50">
                    <div className="flex items-start">
                      <FaTimesCircle className="text-red-500 mr-2 mt-0.5" />
                      <div>
                        <h4 className="font-medium text-red-700">Windows: {key}</h4>
                        <p className="text-sm text-red-600 mt-1">{value.remediation}</p>
                      </div>
                    </div>
                  </div>
                ))}
            {linuxAudit &&
              Object.entries(linuxAudit)
                .filter(([_, value]) => !value.passed && value.severity === "critical")
                .map(([key, value]) => (
                  <div key={`linux-${key}`} className="p-4 border border-red-200 rounded-md bg-red-50">
                    <div className="flex items-start">
                      <FaTimesCircle className="text-red-500 mr-2 mt-0.5" />
                      <div>
                        <h4 className="font-medium text-red-700">Linux: {key}</h4>
                        <p className="text-sm text-red-600 mt-1">{value.remediation}</p>
                      </div>
                    </div>
                  </div>
                ))}
            {networkAudit &&
              Object.entries(networkAudit)
                .filter(([_, value]) => !value.passed && value.severity === "critical")
                .map(([key, value]) => (
                  <div key={`network-${key}`} className="p-4 border border-red-200 rounded-md bg-red-50">
                    <div className="flex items-start">
                      <FaTimesCircle className="text-red-500 mr-2 mt-0.5" />
                      <div>
                        <h4 className="font-medium text-red-700">Network: {key}</h4>
                        <p className="text-sm text-red-600 mt-1">{value.remediation}</p>
                      </div>
                    </div>
                  </div>
                ))}
            {webserverAudit &&
              Object.entries(webserverAudit)
                .filter(([_, value]) => !value.passed && value.severity === "critical")
                .map(([key, value]) => (
                  <div key={`webserver-${key}`} className="p-4 border border-red-200 rounded-md bg-red-50">
                    <div className="flex items-start">
                      <FaTimesCircle className="text-red-500 mr-2 mt-0.5" />
                      <div>
                        <h4 className="font-medium text-red-700">Web Server: {key}</h4>
                        <p className="text-sm text-red-600 mt-1">{value.remediation}</p>
                      </div>
                    </div>
                  </div>
                ))}
            {networkTrafficAudit &&
              Object.entries(networkTrafficAudit)
                .filter(([_, value]) => !value.passed && value.severity === "critical")
                .map(([key, value]) => (
                  <div key={`network-traffic-${key}`} className="p-4 border border-red-200 rounded-md bg-red-50">
                    <div className="flex items-start">
                      <FaTimesCircle className="text-red-500 mr-2 mt-0.5" />
                      <div>
                        <h4 className="font-medium text-red-700">Network Traffic: {key}</h4>
                        <p className="text-sm text-red-600 mt-1">{value.remediation}</p>
                      </div>
                    </div>
                  </div>
                ))}
            {predictiveAnalysis &&
              Object.entries(predictiveAnalysis)
                .filter(([_, value]) => !value.passed && value.severity === "critical")
                .map(([key, value]) => (
                  <div key={`predictive-${key}`} className="p-4 border border-red-200 rounded-md bg-red-50">
                    <div className="flex items-start">
                      <FaTimesCircle className="text-red-500 mr-2 mt-0.5" />
                      <div>
                        <h4 className="font-medium text-red-700">Predictive Analysis: {key}</h4>
                        <p className="text-sm text-red-600 mt-1">{value.remediation}</p>
                      </div>
                    </div>
                  </div>
                ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-8">
            <FaCheckCircle className="text-green-500 text-4xl mb-2" />
            <p className="text-green-600 font-medium">No critical issues found</p>
          </div>
        )}
      </div>
    </>
  )

  const renderReportSection = () => (
    <div className="mb-6 border rounded-lg shadow-sm p-4">
      <div className="flex items-center mb-4">
        <FaFilePdf className="mr-2 text-xl text-red-500" />
        <h2 className="text-2xl font-semibold">PDF Reports</h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="border rounded-lg p-4 flex flex-col items-center">
          <FaWindows className="text-4xl text-blue-500 mb-2" />
          <h3 className="font-medium mb-2">Windows Audit Report</h3>
          <Button
            variant="outline"
            size="sm"
            onClick={() => generateIndividualReport("windows")}
            disabled={!windowsAudit || generatingReport.windows}
            className="w-full"
          >
            {generatingReport.windows ? <FaSync className="animate-spin mr-2" /> : <FaFileDownload className="mr-2" />}
            {generatingReport.windows ? "Generating..." : "Download PDF"}
          </Button>
        </div>

        <div className="border rounded-lg p-4 flex flex-col items-center">
          <FaLinux className="text-4xl text-orange-500 mb-2" />
          <h3 className="font-medium mb-2">Linux Audit Report</h3>
          <Button
            variant="outline"
            size="sm"
            onClick={() => generateIndividualReport("linux")}
            disabled={!linuxAudit || generatingReport.linux}
            className="w-full"
          >
            {generatingReport.linux ? <FaSync className="animate-spin mr-2" /> : <FaFileDownload className="mr-2" />}
            {generatingReport.linux ? "Generating..." : "Download PDF"}
          </Button>
        </div>

        <div className="border rounded-lg p-4 flex flex-col items-center">
          <FaNetworkWired className="text-4xl text-purple-500 mb-2" />
          <h3 className="font-medium mb-2">Network Audit Report</h3>
          <Button
            variant="outline"
            size="sm"
            onClick={() => generateIndividualReport("router")}
            disabled={!networkAudit || generatingReport.network}
            className="w-full"
          >
            {generatingReport.network ? <FaSync className="animate-spin mr-2" /> : <FaFileDownload className="mr-2" />}
            {generatingReport.network ? "Generating..." : "Download PDF"}
          </Button>
        </div>

        <div className="border rounded-lg p-4 flex flex-col items-center">
          <FaServer className="text-4xl text-green-500 mb-2" />
          <h3 className="font-medium mb-2">Web Server Audit Report</h3>
          <Button
            variant="outline"
            size="sm"
            onClick={() => generateIndividualReport("webserver")}
            disabled={!webserverAudit || generatingReport.webserver}
            className="w-full"
          >
            {generatingReport.webserver ? (
              <FaSync className="animate-spin mr-2" />
            ) : (
              <FaFileDownload className="mr-2" />
            )}
            {generatingReport.webserver ? "Generating..." : "Download PDF"}
          </Button>
        </div>
      </div>

      <div className="flex justify-center mt-4">
        <Button
          onClick={generateReport}
          disabled={(!windowsAudit && !linuxAudit && !networkAudit && !webserverAudit) || generatingReport.all}
          className="flex items-center space-x-2"
        >
          {generatingReport.all ? <FaSync className="animate-spin mr-2" /> : <FaFilePdf className="mr-2" />}
          <span>{generatingReport.all ? "Generating Reports..." : "Generate All PDF Reports"}</span>
        </Button>
      </div>
    </div>
  )

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      setNetworkTrafficFile(file)
    }
  }

  const processNetworkTrafficFile = async () => {
    if (!networkTrafficFile) return

    setIsProcessingUpload(true)
    try {
      // In a real application, you would send this file to the backend
      // For now, we'll simulate processing with a timeout
      setTimeout(() => {
        // Mock data that would come from processing the CSV
        const mockData = {
          "CSV File Analysis": {
            passed: true,
            result: {
              details: `Analyzed traffic data from ${networkTrafficFile.name}`,
              timestamp: new Date().toISOString(),
              records_processed: Math.floor(Math.random() * 10000) + 1000,
            },
            severity: "low",
          },
          "Unusual Traffic Patterns": {
            passed: false,
            result: {
              details: "Detected unusual traffic patterns in uploaded data",
              timestamp: new Date().toISOString(),
              anomalies: ["Spike at 14:30", "Unusual destination IPs", "Protocol anomalies"],
            },
            severity: "high",
            remediation: "Investigate the unusual traffic patterns identified in the analysis.",
          },
          "Potential Data Exfiltration": {
            passed: false,
            result: {
              details: "Possible data exfiltration detected in historical data",
              timestamp: new Date().toISOString(),
              suspicious_transfers: [
                { destination: "203.0.113.x", size: "2.3GB", time: "2023-03-15 02:30:45" },
                { destination: "198.51.100.x", size: "1.7GB", time: "2023-03-16 03:15:22" },
              ],
            },
            severity: "critical",
            remediation: "Immediately investigate these transfers and check affected systems for compromise.",
          },
          "Traffic Volume Analysis": {
            passed: true,
            result: {
              details: "Traffic volume within expected parameters",
              average_daily: "1.2TB",
              peak_times: ["09:00-11:00", "14:00-16:00"],
            },
            severity: "low",
          },
          "Connection Analysis": {
            passed: true,
            result: {
              details: "Connection patterns analysis",
              total_connections: 25678,
              unique_destinations: 342,
              most_frequent: ["10.0.0.15", "10.0.0.23", "172.16.1.5"],
            },
            severity: "low",
          },
        }

        setNetworkTrafficAudit(mockData)
        setIsProcessingUpload(false)
      }, 2000)
    } catch (error) {
      console.error("Error processing network traffic file:", error)
      setIsProcessingUpload(false)
    }
  }

  const renderNetworkTrafficSection = () => (
    <>
      <div className="flex flex-col md:flex-row gap-4 mb-6">
        <div className="flex items-center">
          <FaFilter className="mr-2" />
          <span className="font-medium">Filter by:</span>
        </div>
        <div className="grid grid-cols-2 gap-2 md:flex md:items-center md:space-x-2">
          <select
            className="border rounded-md p-2"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            className="border rounded-md p-2"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">All Status</option>
            <option value="passed">Passed</option>
            <option value="failed">Failed</option>
          </select>
        </div>
      </div>

      <div className="mb-6 border rounded-lg shadow-sm p-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <FaNetworkWired className="mr-2 text-xl" />
            <h2 className="text-2xl font-semibold">Network Traffic Analysis</h2>
          </div>
          <div className="flex space-x-2">
            <Button
              variant={networkTrafficMode === "realtime" ? "default" : "outline"}
              onClick={() => setNetworkTrafficMode("realtime")}
              className="flex items-center"
            >
              <FaSync className="mr-2" />
              Realtime Audit
            </Button>
            <Button
              variant={networkTrafficMode === "upload" ? "default" : "outline"}
              onClick={() => setNetworkTrafficMode("upload")}
              className="flex items-center"
            >
              <FaFileUpload className="mr-2" />
              Upload CSV
            </Button>
            <Button
              variant={networkTrafficMode === "ml-analysis" ? "default" : "outline"}
              onClick={() => setNetworkTrafficMode("ml-analysis")}
              className="flex items-center"
            >
              <FaRobot className="mr-2" />
              ML Analysis
            </Button>
          </div>
        </div>

        {networkTrafficMode === "realtime" ? (
          <>
            <div className="mb-4">
              <Button onClick={fetchNetworkTraffic} disabled={loading} className="flex items-center space-x-2">
                {loading ? <FaSync className="animate-spin" /> : <FaNetworkWired />}
                <span>{loading ? "Analyzing..." : "Run Realtime Network Traffic Audit"}</span>
              </Button>
            </div>
            {renderAuditSection(
              "Realtime Network Traffic Analysis",
              networkTrafficAudit,
              <FaNetworkWired />,
              networkTrafficScore,
              "network-traffic",
            )}
          </>
        ) : networkTrafficMode === "upload" ? (
          <div className="mb-6">
            <div className="border rounded-lg p-4 mb-4">
              <h3 className="font-medium mb-2">Upload Network Traffic CSV File</h3>
              <p className="text-sm text-gray-500 mb-4">
                Upload a CSV file containing network traffic data for analysis. The file should include timestamp,
                source IP, destination IP, protocol, and data volume columns.
              </p>
              <div className="flex flex-col md:flex-row gap-4">
                <div className="flex-1">
                  <input
                    type="file"
                    accept=".csv"
                    onChange={handleFileUpload}
                    className="block w-full text-sm text-gray-500
                      file:mr-4 file:py-2 file:px-4
                      file:rounded-md file:border-0
                      file:text-sm file:font-semibold
                      file:bg-primary file:text-white
                      hover:file:bg-primary/90"
                  />
                </div>
                <Button
                  onClick={processNetworkTrafficFile}
                  disabled={!networkTrafficFile || isProcessingUpload}
                  className="flex items-center space-x-2"
                >
                  {isProcessingUpload ? <FaSync className="animate-spin" /> : <FaChartLine />}
                  <span>{isProcessingUpload ? "Processing..." : "Analyze File"}</span>
                </Button>
              </div>
              {networkTrafficFile && (
                <div className="mt-2 text-sm text-gray-500">
                  Selected file: {networkTrafficFile.name} ({(networkTrafficFile.size / 1024).toFixed(2)} KB)
                </div>
              )}
            </div>

            {networkTrafficAudit &&
              networkTrafficMode === "upload" &&
              renderAuditSection(
                "CSV Network Traffic Analysis",
                networkTrafficAudit,
                <FaFileAlt />,
                networkTrafficScore,
                "network-traffic",
              )}
          </div>
        ) : (
          <div className="mb-6">
            <div className="border rounded-lg p-4 mb-4">
              <h3 className="font-medium mb-2">ML-Based Network Traffic Analysis</h3>
              <p className="text-sm text-gray-500 mb-4">
                This feature uses machine learning to analyze network packets in real-time and detect potential
                intrusions or anomalies. The analysis is performed by a trained SVM model that classifies packets as
                normal or intrusion.
              </p>

              <div className="flex flex-col md:flex-row gap-4 mb-4">
                <Button
                  onClick={startMlCapture}
                  disabled={isCapturing}
                  className="flex items-center space-x-2"
                  variant="default"
                >
                  <FaPlay className="mr-2" />
                  <span>Start Capture</span>
                </Button>

                <Button
                  onClick={stopMlCapture}
                  disabled={!isCapturing}
                  className="flex items-center space-x-2"
                  variant="outline"
                >
                  <FaStop className="mr-2" />
                  <span>Stop Capture</span>
                </Button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div className="border rounded-lg p-3 bg-gray-50">
                  <h4 className="text-sm font-medium text-gray-500 mb-1">Total Packets</h4>
                  <div className="text-2xl font-bold">{captureStats.total}</div>
                </div>

                <div className="border rounded-lg p-3 bg-green-50">
                  <h4 className="text-sm font-medium text-gray-500 mb-1">Normal Traffic</h4>
                  <div className="text-2xl font-bold text-green-600">{captureStats.normal}</div>
                </div>

                <div className="border rounded-lg p-3 bg-red-50">
                  <h4 className="text-sm font-medium text-gray-500 mb-1">Intrusion Attempts</h4>
                  <div className="text-2xl font-bold text-red-600">{captureStats.intrusion}</div>
                </div>
              </div>

              <div className="border rounded-lg p-4">
                <h4 className="font-medium mb-2">Packet Analysis Results</h4>
                {isCapturing ? (
                  <div className="text-sm text-green-600 mb-2">
                    <FaSync className="inline-block animate-spin mr-1" /> Capturing packets in real-time...
                  </div>
                ) : (
                  <div className="text-sm text-gray-500 mb-2">
                    {captureStats.total > 0
                      ? "Capture stopped. Results below."
                      : "Click 'Start Capture' to begin analysis."}
                  </div>
                )}

                {mlPackets.length > 0 ? (
                  <div className="max-h-96 overflow-y-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th
                            scope="col"
                            className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                          >
                            Packet
                          </th>
                          <th
                            scope="col"
                            className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                          >
                            Classification
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {mlPackets.map((packet, index) => (
                          <tr key={index}>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{packet.summary}</td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span
                                className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                  packet.prediction === "Normal"
                                    ? "bg-green-100 text-green-800"
                                    : "bg-red-100 text-red-800"
                                }`}
                              >
                                {packet.prediction}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-8">
                    <FaNetworkWired className="text-gray-400 text-4xl mb-2" />
                    <p className="text-gray-500">No packets captured yet</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  )

  return (
    <div className="container mx-auto p-4">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between mb-6">
        <div>
          <h1 className="text-4xl font-bold mb-1">Security Audit Dashboard</h1>
          {lastAuditTime && <p className="text-gray-500">Last Audit Performed: {lastAuditTime}</p>}
        </div>
        <div className="flex flex-wrap gap-2 mt-4 md:mt-0">
          <Button onClick={() => performAudit("windows")} disabled={loading} className="flex items-center space-x-2">
            {loading ? <FaSync className="animate-spin" /> : <FaWindows />}
            <span>{loading ? "Auditing..." : "Audit Windows"}</span>
          </Button>
          <Button onClick={() => performAudit("linux")} disabled={loading} className="flex items-center space-x-2">
            {loading ? <FaSync className="animate-spin" /> : <FaLinux />}
            <span>{loading ? "Auditing..." : "Audit Linux"}</span>
          </Button>
          <Button onClick={() => performAudit("router")} disabled={loading} className="flex items-center space-x-2">
            {loading ? <FaSync className="animate-spin" /> : <FaNetworkWired />}
            <span>{loading ? "Auditing..." : "Audit Network Infra"}</span>
          </Button>
          <Button onClick={() => performAudit("webserver")} disabled={loading} className="flex items-center space-x-2">
            {loading ? <FaSync className="animate-spin" /> : <FaServer />}
            <span>{loading ? "Auditing..." : "Audit Web Server"}</span>
          </Button>
          <Button onClick={fetchNetworkTraffic} disabled={loading} className="flex items-center space-x-2">
            {loading ? <FaSync className="animate-spin" /> : <FaNetworkWired />}
            <span>{loading ? "Analyzing..." : "Audit Network Traffic"}</span>
          </Button>
          <Button onClick={fetchPredictiveAnalysis} disabled={loading} className="flex items-center space-x-2">
            {loading ? <FaSync className="animate-spin" /> : <FaShieldAlt />}
            <span>{loading ? "Analyzing..." : "Predictive Analysis"}</span>
          </Button>
        </div>
      </div>

      <div className="mb-6 border-b">
        <div className="flex space-x-4">
          <button
            className={`px-4 py-2 font-medium ${activeTab === "dashboard" ? "border-b-2 border-primary text-primary" : "text-gray-500"}`}
            onClick={() => setActiveTab("dashboard")}
          >
            <div className="flex items-center">
              <FaShieldAlt className="mr-2" />
              Dashboard
            </div>
          </button>
          <button
            className={`px-4 py-2 font-medium ${activeTab === "results" ? "border-b-2 border-primary text-primary" : "text-gray-500"}`}
            onClick={() => setActiveTab("results")}
          >
            <div className="flex items-center">
              <FaServer className="mr-2" />
              Audit Results
            </div>
          </button>
          <button
            className={`px-4 py-2 font-medium ${activeTab === "history" ? "border-b-2 border-primary text-primary" : "text-gray-500"}`}
            onClick={() => setActiveTab("history")}
          >
            <div className="flex items-center">
              <FaHistory className="mr-2" />
              History
            </div>
          </button>
          <button
            className={`px-4 py-2 font-medium ${activeTab === "network-traffic" ? "border-b-2 border-primary text-primary" : "text-gray-500"}`}
            onClick={() => setActiveTab("network-traffic")}
          >
            <div className="flex items-center">
              <FaNetworkWired className="mr-2" />
              Network Traffic
            </div>
          </button>
          <button
            className={`px-4 py-2 font-medium ${activeTab === "predictive" ? "border-b-2 border-primary text-primary" : "text-gray-500"}`}
            onClick={() => setActiveTab("predictive")}
          >
            <div className="flex items-center">
              <FaShieldAlt className="mr-2" />
              Predictive Analysis
            </div>
          </button>
          <button
            className={`px-4 py-2 font-medium ${activeTab === "reports" ? "border-b-2 border-primary text-primary" : "text-gray-500"}`}
            onClick={() => setActiveTab("reports")}
          >
            <div className="flex items-center">
              <FaFilePdf className="mr-2" />
              Reports
            </div>
          </button>
        </div>
      </div>

      {activeTab === "dashboard" && renderDashboard()}

      {activeTab === "results" && (
        <>
          <div className="flex flex-col md:flex-row gap-4 mb-6">
            <div className="flex items-center">
              <FaFilter className="mr-2" />
              <span className="font-medium">Filter by:</span>
            </div>
            <div className="grid grid-cols-2 gap-2 md:flex md:items-center md:space-x-2">
              <select
                className="border rounded-md p-2"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                className="border rounded-md p-2"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="all">All Status</option>
                <option value="passed">Passed</option>
                <option value="failed">Failed</option>
              </select>
            </div>
          </div>

          {renderAuditSection("Windows Audit", windowsAudit, <FaWindows />, windowsScore, "windows")}
          {renderAuditSection("Linux Audit", linuxAudit, <FaLinux />, linuxScore, "linux")}
          {renderAuditSection("Network Infrastructure Audit", networkAudit, <FaNetworkWired />, networkScore, "router")}
          {renderAuditSection("Web Server Audit", webserverAudit, <FaServer />, webserverScore, "webserver")}
        </>
      )}

      {activeTab === "network-traffic" && renderNetworkTrafficSection()}

      {activeTab === "predictive" && (
        <>
          <div className="flex flex-col md:flex-row gap-4 mb-6">
            <div className="flex items-center">
              <FaFilter className="mr-2" />
              <span className="font-medium">Filter by:</span>
            </div>
            <div className="grid grid-cols-2 gap-2 md:flex md:items-center md:space-x-2">
              <select
                className="border rounded-md p-2"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                className="border rounded-md p-2"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="all">All Status</option>
                <option value="passed">Passed</option>
                <option value="failed">Failed</option>
              </select>
            </div>
          </div>
          {renderAuditSection(
            "Infrastructure Security Prediction",
            predictiveAnalysis,
            <FaShieldAlt />,
            predictiveScore,
            "predictive",
          )}
        </>
      )}

      {activeTab === "reports" && renderReportSection()}

      {activeTab === "history" && renderAuditHistory()}
    </div>
  )
}

