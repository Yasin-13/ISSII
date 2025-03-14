import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"

interface SecuritySectionProps {
  title: string
  data: string | object
}

export default function SecuritySection({ title, data }: SecuritySectionProps) {
  return (
    <Accordion type="single" collapsible>
      <AccordionItem value={title}>
        <AccordionTrigger>{title}</AccordionTrigger>
        <AccordionContent>
          <pre className="whitespace-pre-wrap overflow-x-auto">
            {typeof data === "object" ? JSON.stringify(data, null, 2) : data}
          </pre>
        </AccordionContent>
      </AccordionItem>
    </Accordion>
  )
}

