"use client"

import { Button } from "@/components/ui/button"
import { useState } from "react"

export default function GenerateReportButton() {
  const [isGenerating, setIsGenerating] = useState(false)

  const handleGenerateReport = async () => {
    setIsGenerating(true)
    try {
      const response = await fetch("/generate_report")
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = "security_audit_report.pdf"
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error("Error generating report:", error)
    } finally {
      setIsGenerating(false)
    }
  }

  return (
    <Button onClick={handleGenerateReport} disabled={isGenerating}>
      {isGenerating ? "Generating..." : "Generate PDF Report"}
    </Button>
  )
}

