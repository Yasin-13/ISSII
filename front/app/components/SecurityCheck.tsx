import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { CheckCircle, XCircle } from "lucide-react"

interface SecurityCheckProps {
  title: string
  status: string
}

export default function SecurityCheck({ title, status }: SecurityCheckProps) {
  const isEnabled = status.toLowerCase() === "enabled"

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          {title}
          {isEnabled ? <CheckCircle className="text-green-500" /> : <XCircle className="text-red-500" />}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className={isEnabled ? "text-green-500" : "text-red-500"}>{status}</p>
      </CardContent>
    </Card>
  )
}

