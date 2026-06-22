import type { AnalysisIssue } from "@/lib/analyzer";
import type { PreviewIssue } from "@/lib/types";

// Strips fix/codefix from an issue list. Same projection currently inlined
// in app/api/scan/route.ts — kept here as the reusable, named version.
export function toPreviewIssues(issues: AnalysisIssue[]): PreviewIssue[] {
  return issues.map(({ title, severity, consequence }) => ({ title, severity, consequence }));
}
