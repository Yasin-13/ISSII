"use client"

// Simplified version of the useToast hook
import { useState } from "react"

type ToastProps = {
  title?: string
  description?: string
  variant?: "default" | "destructive"
}

export function useToast() {
  const [toasts, setToasts] = useState<ToastProps[]>([])

  const toast = (props: ToastProps) => {
    // In a real implementation, this would add the toast to a state
    // and display it in the UI. For now, we'll just log it to the console
    console.log("Toast:", props)
    return { id: Date.now().toString() }
  }

  return {
    toast,
    toasts,
    dismiss: (id: string) => {
      // This would remove the toast with the given ID
    },
  }
}

