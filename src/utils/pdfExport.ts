import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ScanResult, Finding, Severity, MultiFileScanResult } from '@/types/scanner';
import { getFileTypeLabel } from '@/utils/fileDetector';
import { SITE } from '@/config/site';

export function generatePdfReport(
  scanResult: ScanResult,
  filteredFindings?: Finding[]
): void {
  const doc = new jsPDF();
  const findings = filteredFindings || scanResult.findings;
  
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 20;
  const headerHeight = 35;
  // Footer height: links (5) + spacing (3) + disclaimer (estimated 3 lines * 3.5) + spacing (3) + page info (5) + margin (5) = ~35
  const footerHeight = 50; // Increased to accommodate all footer content
  const contentWidth = pageWidth - (margin * 2);
  const contentBottom = pageHeight - footerHeight; // Safe area for content
  let yPos = headerHeight + 8; // Start after header
  
  // Metadata Section with better alignment
  doc.setFontSize(10);
  doc.setTextColor(60, 60, 60);
  doc.setFont('helvetica', 'normal');
  
  const timestamp = scanResult.timestamp.toLocaleString();
  const fileType = scanResult.parsedFile 
    ? getFileTypeLabel(scanResult.parsedFile.fileType) 
    : 'Unknown';
  const fileName = scanResult.parsedFile?.fileName || 'Unknown';
  
  const metadataItems = [
    { label: 'Generated:', value: timestamp },
    { label: 'File:', value: fileName },
    { label: 'File Type:', value: fileType },
  ];
  
  const executedRules = scanResult.ruleExecutions.filter(r => r.status === 'executed').length;
  metadataItems.push({ label: 'Rules Executed:', value: `${executedRules} of ${scanResult.ruleExecutions.length}` });
  
  // Draw metadata box
  const metadataBoxHeight = metadataItems.length * 8 + 10;
  doc.setDrawColor(200, 200, 200);
  doc.setLineWidth(0.5);
  doc.roundedRect(margin, yPos, contentWidth, metadataBoxHeight, 2, 2, 'S');
  
  let metadataY = yPos + 8;
  for (const item of metadataItems) {
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(60, 60, 60);
    doc.text(item.label, margin + 5, metadataY);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 100, 100);
    doc.text(item.value, margin + 45, metadataY);
    metadataY += 8;
  }
  
  yPos += metadataBoxHeight + 15;
  
  // Summary Box - Professional aligned design
  const severityCounts = getSeverityCounts(findings);
  const totalIssues = findings.length;
  
  const summaryBoxHeight = 35;
  const summaryBoxWidth = contentWidth; // Use full content width
  doc.setFillColor(30, 41, 59); // Darker professional blue
  doc.roundedRect(margin, yPos, summaryBoxWidth, summaryBoxHeight, 3, 3, 'F');
  
  // Summary title
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text('Summary', margin + 8, yPos + 12);
  
  // Summary items in aligned boxes
  doc.setFontSize(10);
  const summaryY = yPos + 25;
  const summaryItemWidth = (contentWidth - 20) / 4;
  let summaryX = margin + 10;
  
  // Total box
  doc.setFillColor(255, 255, 255);
  doc.roundedRect(summaryX, summaryY - 8, summaryItemWidth - 5, 12, 2, 2, 'F');
  doc.setTextColor(60, 60, 60);
  doc.setFont('helvetica', 'bold');
  doc.text(`Total: ${totalIssues}`, summaryX + 3, summaryY);
  summaryX += summaryItemWidth;
  
  // High box
  doc.setFillColor(239, 68, 68);
  doc.roundedRect(summaryX, summaryY - 8, summaryItemWidth - 5, 12, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.text(`High: ${severityCounts.HIGH || 0}`, summaryX + 3, summaryY);
  summaryX += summaryItemWidth;
  
  // Medium box
  doc.setFillColor(245, 158, 11);
  doc.roundedRect(summaryX, summaryY - 8, summaryItemWidth - 5, 12, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.text(`Medium: ${severityCounts.MEDIUM || 0}`, summaryX + 3, summaryY);
  summaryX += summaryItemWidth;
  
  // Low box
  doc.setFillColor(59, 130, 246);
  doc.roundedRect(summaryX, summaryY - 8, summaryItemWidth - 5, 12, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.text(`Low: ${severityCounts.LOW || 0}`, summaryX + 3, summaryY);
  
  yPos += summaryBoxHeight + 15;
  
  // Findings Table
  if (findings.length > 0) {
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 41, 59);
    doc.text('Findings', margin, yPos);
    yPos += 8;
    
    const tableData = findings.map(finding => [
      finding.ruleId,
      finding.title,
      finding.severity,
      finding.resourcePath || '-',
      finding.lineNumber?.toString() || '-',
    ]);
    
    autoTable(doc, {
      startY: yPos,
      margin: { 
        left: margin, 
        right: margin, 
        top: headerHeight + 10, // Reserve space for header on new pages
        bottom: footerHeight + 5 // Reserve space for footer
      },
      head: [['Rule ID', 'Title', 'Severity', 'Resource', 'Line']],
      body: tableData,
      theme: 'striped',
      pageBreak: 'auto',
      showHead: 'everyPage',
      headStyles: {
        fillColor: [30, 41, 59],
        textColor: [255, 255, 255],
        fontStyle: 'bold',
        fontSize: 8,
        halign: 'center',
        cellPadding: { top: 3, bottom: 3, left: 3, right: 3 },
      },
      styles: {
        fontSize: 8,
        cellPadding: { top: 4, bottom: 4, left: 5, right: 5 },
        lineColor: [220, 220, 220],
        lineWidth: 0.5,
      },
      alternateRowStyles: {
        fillColor: [248, 250, 252],
      },
      columnStyles: {
        0: { cellWidth: 24, fontStyle: 'bold', overflow: 'linebreak' },
        1: { cellWidth: 65, halign: 'center' },
        2: { cellWidth: 20, halign: 'center' },
        3: { cellWidth: 42, halign: 'center' },
        4: { cellWidth: 22, halign: 'center' },
      },
      didDrawPage: (data) => {
        // Ensure proper spacing on new pages
        if (data.pageNumber > 1) {
          // Adjust starting position for continuation pages
          if (data.cursor) {
            data.cursor.y = Math.max(data.cursor.y, headerHeight + 15);
          }
        }
      },
      didDrawCell: (data) => {
        // Prevent Rule ID from wrapping
        if (data.section === 'body' && data.column.index === 0) {
          data.cell.styles.fontSize = 7;
        }
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 2) {
          const severity = data.cell.raw as string;
          if (severity === 'HIGH') {
            data.cell.styles.textColor = [239, 68, 68];
            data.cell.styles.fontStyle = 'bold';
          } else if (severity === 'MEDIUM') {
            data.cell.styles.textColor = [245, 158, 11];
            data.cell.styles.fontStyle = 'bold';
          } else if (severity === 'LOW') {
            data.cell.styles.textColor = [59, 130, 246];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    
    // Add detailed findings on new pages
    const finalY = (doc as unknown as { lastAutoTable?: { finalY?: number } }).lastAutoTable?.finalY || yPos + 50;
    
    if (findings.length > 0 && finalY < contentBottom - 20) {
      yPos = finalY + 15;
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 41, 59);
      doc.text('Remediation Details', margin, yPos);
      yPos += 12;
      
      for (const finding of findings.slice(0, 5)) {
        // Format remediation first to calculate box height
        const remediation = finding.remediation || 'No remediation provided.';
        const formattedRemediation = formatRemediationText(remediation, contentWidth - 20, doc);
        
        // Calculate total height needed
        const titleHeight = 8;
        const remediationHeight = formattedRemediation.reduce((sum, line) => sum + (line.height || 4.5), 0);
        const padding = 12;
        const boxHeight = titleHeight + remediationHeight + padding;
        const spacing = 10;
        const totalNeeded = boxHeight + spacing;
        
        // Check if we need a new page before starting a new finding
        if (yPos + totalNeeded > contentBottom) {
          doc.addPage();
          yPos = headerHeight + 15;
        }
        
        // Draw finding box with dynamic height
        doc.setDrawColor(220, 220, 220);
        doc.setLineWidth(0.5);
        doc.setFillColor(255, 255, 255);
        doc.roundedRect(margin, yPos, contentWidth, boxHeight, 2, 2, 'FD');
        
        // Title
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(30, 41, 59);
        doc.text(`${finding.ruleId}: ${finding.title}`, margin + 8, yPos + 8);
        
        // Remediation text
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8.5);
        doc.setTextColor(80, 80, 80);
        
        let remediationY = yPos + titleHeight + 6;
        for (const line of formattedRemediation) {
          // Check if we need a new page mid-remediation (with buffer)
          if (remediationY + 4.5 > contentBottom) {
            doc.addPage();
            remediationY = headerHeight + 15;
            // Redraw box on new page
            const remainingHeight = boxHeight - (remediationY - (yPos + titleHeight + 6));
            doc.roundedRect(margin, remediationY - titleHeight - 6, contentWidth, remainingHeight, 2, 2, 'FD');
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(10);
            doc.text(`${finding.ruleId}: ${finding.title}`, margin + 8, remediationY - titleHeight + 2);
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(8.5);
          }
          doc.text(line.text, margin + 8, remediationY);
          remediationY += line.height || 4.5;
        }
        
        yPos = yPos + boxHeight + spacing; // Add spacing between findings
      }
    }
  } else {
    // No findings - success message
    doc.setFillColor(240, 253, 244);
    doc.roundedRect(margin, yPos, contentWidth, 30, 3, 3, 'F');
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(34, 197, 94);
    doc.text('✓ No security issues found!', margin + 10, yPos + 18);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(100, 100, 100);
    doc.text('Your infrastructure code follows security best practices.', margin + 10, yPos + 25);
  }
  
  // Header and Footer on all pages
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    
    // Add header to all pages
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, headerHeight, 'F');
    
    // No logo - clean text-only header
    
    doc.setFontSize(18);
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.text('IaC Security Scan Report', pageWidth / 2, 15, { align: 'center' });
    
    doc.setFontSize(8);
    doc.setTextColor(200, 200, 200);
    doc.setFont('helvetica', 'normal');
    const subtitleText1 = 'IAC Security Scanner on ';
    const linkText = 'peachycloudsecurity.com';
    const subtitleText2 = ' (theshukladuo)';
    const subtitle1Width = doc.getTextWidth(subtitleText1);
    const linkWidth = doc.getTextWidth(linkText);
    const subtitle2Width = doc.getTextWidth(subtitleText2);
    const totalWidth = subtitle1Width + linkWidth + subtitle2Width;
    const subtitleX = (pageWidth - totalWidth) / 2;
    
    doc.text(subtitleText1, subtitleX, 23);
    doc.setTextColor(100, 180, 255);
    doc.text(linkText, subtitleX + subtitle1Width, 23);
    doc.link(subtitleX + subtitle1Width, 20, linkWidth, 3, { url: 'https://peachycloudsecurity.com' });
    doc.setTextColor(200, 200, 200);
    doc.text(subtitleText2, subtitleX + subtitle1Width + linkWidth, 23);
    
    // Header links row
    doc.setFontSize(7);
    doc.setTextColor(180, 180, 180);
    doc.setFont('helvetica', 'normal');
    
    const headerLinks = [
      { text: 'Peachycloud Security', url: 'https://peachycloudsecurity.com' },
      { text: 'Book Session', url: SITE.links.topmate },
      { text: 'Buy me a coffee', url: SITE.links.kofi },
      { text: 'Subscribe Youtube ', url: SITE.youtube.subscribeUrl },
      { text: 'GitHub', url: 'https://github.com/peachycloudsecurity/iac-security-scanner' }
    ];
    
    const totalLinksWidth = headerLinks.reduce((sum, link) => sum + doc.getTextWidth(link.text), 0);
    const separatorsWidth = (headerLinks.length - 1) * doc.getTextWidth(' | ');
    const linksStartX = (pageWidth - (totalLinksWidth + separatorsWidth)) / 2;
    
    let headerLinkX = linksStartX;
    const headerLinkY = 30;
    
    for (let j = 0; j < headerLinks.length; j++) {
      const link = headerLinks[j];
      doc.setTextColor(180, 180, 180);
      doc.text(link.text, headerLinkX, headerLinkY);
      doc.link(headerLinkX, headerLinkY - 2, doc.getTextWidth(link.text), 3, { url: link.url });
      headerLinkX += doc.getTextWidth(link.text);
      
      if (j < headerLinks.length - 1) {
        doc.setTextColor(120, 120, 120);
        doc.text(' | ', headerLinkX, headerLinkY);
        headerLinkX += doc.getTextWidth(' | ');
      }
    }
    
    // Calculate footer position - start from bottom
    const pageInfoY = pageHeight - 5;
    const pageInfoHeight = 5;
    
    // Disclaimer (above page info)
    doc.setFontSize(6);
    doc.setTextColor(100, 100, 100);
    const wrappedDisclaimer = doc.splitTextToSize(SITE.disclaimer, contentWidth);
    const disclaimerHeight = wrappedDisclaimer.length * 3.5;
    const disclaimerY = pageInfoY - pageInfoHeight - disclaimerHeight - 3;
    
    // Links row (above disclaimer)
    const linkY = disclaimerY - 8;
    const footerY = linkY - 5;
    
    // Footer line
    doc.setDrawColor(220, 220, 220);
    doc.setLineWidth(0.5);
    doc.line(margin, footerY, pageWidth - margin, footerY);
    
    // Footer content
    doc.setFontSize(7);
    doc.setTextColor(120, 120, 120);
    doc.setFont('helvetica', 'normal');
    
    // Links row
    let footerX = margin;
    const linkSpacing = 8;
    
    // Peachycloud Security link
    doc.setTextColor(100, 180, 255);
    doc.text('Peachycloud Security', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('Peachycloud Security'), 4, { url: 'https://peachycloudsecurity.com' });
    footerX += doc.getTextWidth('Peachycloud Security') + linkSpacing;
    
    doc.setTextColor(120, 120, 120);
    doc.text('|', footerX, linkY);
    footerX += 5;
    
    // Book Session link
    doc.setTextColor(100, 180, 255);
    doc.text('Book Session', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('Book Session'), 4, { url: SITE.links.topmate });
    footerX += doc.getTextWidth('Book Session') + linkSpacing;
    
    doc.setTextColor(120, 120, 120);
    doc.text('|', footerX, linkY);
    footerX += 5;
    
    // Buy me a coffee link
    doc.setTextColor(100, 180, 255);
    doc.text('Buy me a coffee', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('Buy me a coffee'), 4, { url: SITE.links.kofi });
    footerX += doc.getTextWidth('Buy me a coffee') + linkSpacing;
    
    doc.setTextColor(120, 120, 120);
    doc.text('|', footerX, linkY);
    footerX += 5;
    
    // Subscribe YouTube link
    doc.setTextColor(100, 180, 255);
    doc.text('Subscribe YouTube', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('Subscribe YouTube'), 4, { url: SITE.youtube.subscribeUrl });
    footerX += doc.getTextWidth('Subscribe Youtube') + linkSpacing;
    
    doc.setTextColor(120, 120, 120);
    doc.text('|', footerX, linkY);
    footerX += 5;
    
    // GitHub link
    doc.setTextColor(100, 180, 255);
    doc.text('GitHub', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('GitHub'), 4, { url: 'https://github.com/peachycloudsecurity/iac-security-scanner' });
    
    // Disclaimer
    doc.setFontSize(6);
    doc.setTextColor(100, 100, 100);
    for (let j = 0; j < wrappedDisclaimer.length; j++) {
      doc.text(wrappedDisclaimer[j], margin, disclaimerY + (j * 3.5));
    }
    
    // Page info
    doc.setFontSize(7);
    doc.setTextColor(150, 150, 150);
    doc.text(
      `Page ${i} of ${pageCount} | All IAC scanner analysis runs locally in your browser by peachycloudsecurity`,
      pageWidth / 2,
      pageInfoY,
      { align: 'center' }
    );
  }
  
  // Download
  const dateStr = new Date().toISOString().split('T')[0];
  const timeStr = new Date().toTimeString().split(' ')[0].replace(/:/g, '-');
  doc.save(`security-scan-${dateStr}-${timeStr}.pdf`);
}

function getSeverityCounts(findings: Finding[]): Record<Severity, number> {
  return findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<Severity, number>);
}

function formatRemediationText(text: string, maxWidth: number, doc: jsPDF): Array<{ text: string; height: number }> {
  const lines: Array<{ text: string; height: number }> = [];
  
  // Split text by numbered list pattern (1), 2), 3), etc.)
  const numberedPattern = /(\d+\)\s+)/g;
  const parts: Array<{ type: 'text' | 'numbered'; content: string }> = [];
  let lastIndex = 0;
  let match;
  
  // Find all numbered items
  const numberedMatches: Array<{ index: number; content: string }> = [];
  while ((match = numberedPattern.exec(text)) !== null) {
    numberedMatches.push({
      index: match.index,
      content: match[0]
    });
  }
  
  if (numberedMatches.length > 0) {
    // Has numbered list - split text properly
    // Add text before first numbered item
    if (numberedMatches[0].index > 0) {
      const beforeText = text.substring(0, numberedMatches[0].index).trim();
      if (beforeText) {
        parts.push({ type: 'text', content: beforeText });
      }
    }
    
    // Process numbered items
    for (let i = 0; i < numberedMatches.length; i++) {
      const startIndex = numberedMatches[i].index;
      const endIndex = i < numberedMatches.length - 1 
        ? numberedMatches[i + 1].index 
        : text.length;
      const itemText = text.substring(startIndex, endIndex).trim();
      parts.push({ type: 'numbered', content: itemText });
    }
  } else {
    // No numbered list - just add entire text
    parts.push({ type: 'text', content: text.trim() });
  }
  
  // Format each part
  for (const part of parts) {
    if (part.type === 'text') {
      const wrapped = doc.splitTextToSize(part.content, maxWidth);
      for (const line of wrapped) {
        if (line.trim()) {
          lines.push({ text: line, height: 4.5 });
        }
      }
      if (parts.length > 1 && part !== parts[parts.length - 1]) {
        lines.push({ text: '', height: 3 }); // Spacing before numbered list
      }
    } else {
      // Numbered item - wrap with proper indentation
      const wrapped = doc.splitTextToSize(part.content, maxWidth);
      for (let i = 0; i < wrapped.length; i++) {
        lines.push({ 
          text: wrapped[i], 
          height: 4.5 
        });
      }
      // Add small spacing after numbered item
      if (part !== parts[parts.length - 1]) {
        lines.push({ text: '', height: 2 });
      }
    }
  }
  
  return lines;
}

/**
 * Generate PDF report for multi-file GitHub repository scan
 */
export function generateMultiFilePdfReport(
  multiFileResult: MultiFileScanResult,
  repoUrl?: string
): void {
  const doc = new jsPDF();
  const allFindings = multiFileResult.files.flatMap(f => f.findings);
  
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 20;
  const headerHeight = 35;
  const footerHeight = 50;
  const contentWidth = pageWidth - (margin * 2);
  const contentBottom = pageHeight - footerHeight;
  let yPos = headerHeight + 8;
  
  // Metadata Section
  doc.setFontSize(10);
  doc.setTextColor(60, 60, 60);
  doc.setFont('helvetica', 'normal');
  
  const timestamp = multiFileResult.timestamp.toLocaleString();
  
  const metadataItems = [
    { label: 'Generated:', value: timestamp },
    { label: 'Files Scanned:', value: `${multiFileResult.files.length} files` },
  ];
  
  if (repoUrl) {
    metadataItems.push({ label: 'Repository:', value: repoUrl });
  }
  
  // Draw metadata box
  const metadataBoxHeight = metadataItems.length * 8 + 10;
  doc.setDrawColor(200, 200, 200);
  doc.setLineWidth(0.5);
  doc.roundedRect(margin, yPos, contentWidth, metadataBoxHeight, 2, 2, 'S');
  
  let metadataY = yPos + 8;
  for (const item of metadataItems) {
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(60, 60, 60);
    doc.text(item.label, margin + 5, metadataY);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 100, 100);
    const valueText = doc.splitTextToSize(item.value, contentWidth - 50);
    doc.text(valueText, margin + 45, metadataY);
    metadataY += valueText.length > 1 ? valueText.length * 8 : 8;
  }
  
  yPos = metadataY + 10;
  
  // Summary Box
  const summaryBoxHeight = 35;
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin, yPos, contentWidth, summaryBoxHeight, 3, 3, 'F');
  
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text('Summary', margin + 8, yPos + 12);
  
  doc.setFontSize(10);
  const summaryY = yPos + 25;
  const summaryItemWidth = (contentWidth - 20) / 4;
  let summaryX = margin + 10;
  
  // Total box
  doc.setFillColor(255, 255, 255);
  doc.roundedRect(summaryX, summaryY - 8, summaryItemWidth - 5, 12, 2, 2, 'F');
  doc.setTextColor(60, 60, 60);
  doc.setFont('helvetica', 'bold');
  doc.text(`Total: ${allFindings.length}`, summaryX + 3, summaryY);
  summaryX += summaryItemWidth;
  
  // High box
  doc.setFillColor(239, 68, 68);
  doc.roundedRect(summaryX, summaryY - 8, summaryItemWidth - 5, 12, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.text(`High: ${multiFileResult.findingsBySeverity.HIGH}`, summaryX + 3, summaryY);
  summaryX += summaryItemWidth;
  
  // Medium box
  doc.setFillColor(245, 158, 11);
  doc.roundedRect(summaryX, summaryY - 8, summaryItemWidth - 5, 12, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.text(`Medium: ${multiFileResult.findingsBySeverity.MEDIUM}`, summaryX + 3, summaryY);
  summaryX += summaryItemWidth;
  
  // Low box
  doc.setFillColor(59, 130, 246);
  doc.roundedRect(summaryX, summaryY - 8, summaryItemWidth - 5, 12, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.text(`Low: ${multiFileResult.findingsBySeverity.LOW}`, summaryX + 3, summaryY);
  
  yPos += summaryBoxHeight + 15;
  
  // Files with Findings
  const filesWithFindings = multiFileResult.files.filter(f => f.findings.length > 0);
  
  if (filesWithFindings.length > 0) {
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 41, 59);
    doc.text('Findings by File', margin, yPos);
    yPos += 10;
    
    // Create table data for all findings with file names and brief remediation
    const tableData: string[][] = [];
    for (const file of filesWithFindings) {
      for (const finding of file.findings) {
        // Truncate remediation to keep table readable
        const briefRemediation = finding.remediation ? 
          (finding.remediation.length > 80 ? finding.remediation.substring(0, 80) + '...' : finding.remediation) :
          'See details section';
          
        tableData.push([
          file.fileName,
          finding.ruleId,
          finding.title,
          finding.severity,
          finding.resourcePath || '-',
          finding.lineNumber?.toString() || '-',
          briefRemediation,
        ]);
      }
    }
    
    autoTable(doc, {
      startY: yPos,
      margin: { 
        left: margin, 
        right: margin, 
        top: headerHeight + 10,
        bottom: footerHeight + 5
      },
      head: [['File', 'Rule ID', 'Title', 'Severity', 'Resource', 'Line', 'Quick Fix']],
      body: tableData,
      theme: 'striped',
      pageBreak: 'auto',
      showHead: 'everyPage',
      headStyles: {
        fillColor: [30, 41, 59],
        textColor: [255, 255, 255],
        fontStyle: 'bold',
        fontSize: 7,
        halign: 'center',
        cellPadding: { top: 3, bottom: 3, left: 2, right: 2 },
      },
      styles: {
        fontSize: 7,
        cellPadding: { top: 3, bottom: 3, left: 3, right: 3 },
        lineColor: [220, 220, 220],
        lineWidth: 0.5,
      },
      alternateRowStyles: {
        fillColor: [248, 250, 252],
      },
      columnStyles: {
        0: { cellWidth: 30, overflow: 'linebreak' }, // File name
        1: { cellWidth: 15, fontStyle: 'bold', overflow: 'linebreak' }, // Rule ID
        2: { cellWidth: 35, overflow: 'linebreak' }, // Title
        3: { cellWidth: 12, halign: 'center' }, // Severity
        4: { cellWidth: 25, overflow: 'linebreak' }, // Resource
        5: { cellWidth: 8, halign: 'center' }, // Line
        6: { cellWidth: 45, overflow: 'linebreak', fontSize: 6 }, // Quick Fix/Remediation
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 3) {
          const severity = data.cell.raw as string;
          if (severity === 'HIGH') {
            data.cell.styles.textColor = [239, 68, 68];
            data.cell.styles.fontStyle = 'bold';
          } else if (severity === 'MEDIUM') {
            data.cell.styles.textColor = [245, 158, 11];
            data.cell.styles.fontStyle = 'bold';
          } else if (severity === 'LOW') {
            data.cell.styles.textColor = [59, 130, 246];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    
    const finalY = (doc as unknown as { lastAutoTable?: { finalY?: number } }).lastAutoTable?.finalY || yPos + 50;
    yPos = finalY + 15;
    
    // Add detailed findings for all files (same format as single file scan)
    if (filesWithFindings.length > 0) {
      // Flatten all findings from all files
      const allFindings = filesWithFindings.flatMap(f => f.findings);
      
      if (allFindings.length > 0 && finalY < contentBottom - 20) {
        yPos = finalY + 15;
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(30, 41, 59);
        doc.text('Remediation Details', margin, yPos);
        yPos += 12;
        
        // Show findings in same format as single file (limit to prevent extremely long PDFs)
        for (const finding of allFindings.slice(0, 15)) {
          // Format remediation first to calculate box height
          const remediation = finding.remediation || 'No remediation provided.';
          const formattedRemediation = formatRemediationText(remediation, contentWidth - 20, doc);
          
          // Calculate total height needed
          const titleHeight = 8;
          const remediationHeight = formattedRemediation.reduce((sum, line) => sum + (line.height || 4.5), 0);
          const padding = 12;
          const boxHeight = titleHeight + remediationHeight + padding;
          const spacing = 10;
          const totalNeeded = boxHeight + spacing;
          
          // Check if we need a new page before starting a new finding
          if (yPos + totalNeeded > contentBottom) {
            doc.addPage();
            yPos = headerHeight + 15;
          }
          
          // Draw finding box with dynamic height (same as single file)
          doc.setDrawColor(220, 220, 220);
          doc.setLineWidth(0.5);
          doc.setFillColor(255, 255, 255);
          doc.roundedRect(margin, yPos, contentWidth, boxHeight, 2, 2, 'FD');
          
          // Title (same format as single file)
          doc.setFontSize(10);
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(30, 41, 59);
          doc.text(`${finding.ruleId}: ${finding.title}`, margin + 8, yPos + 8);
          
          // Remediation text (same format as single file)
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8.5);
          doc.setTextColor(80, 80, 80);
          
          let remediationY = yPos + titleHeight + 6;
          for (const line of formattedRemediation) {
            // Check if we need a new page mid-remediation (with buffer)
            if (remediationY + 4.5 > contentBottom) {
              doc.addPage();
              remediationY = headerHeight + 15;
              // Handle continuation on new page (same as single file)
              const remainingHeight = boxHeight - (remediationY - (yPos + titleHeight + 6));
              doc.roundedRect(margin, remediationY - titleHeight - 6, contentWidth, remainingHeight, 2, 2, 'FD');
              
              // Redraw title on new page
              doc.setFont('helvetica', 'bold');
              doc.setFontSize(10);
              doc.setTextColor(30, 41, 59);
              doc.text(`${finding.ruleId}: ${finding.title}`, margin + 8, remediationY - titleHeight + 2);
              
              doc.setFont('helvetica', 'normal');
              doc.setFontSize(8.5);
              doc.setTextColor(80, 80, 80);
            }
            doc.text(line.text, margin + 8, remediationY);
            remediationY += line.height || 4.5;
          }
          
          yPos = yPos + boxHeight + spacing;
        }
        
        // Add note if there are more findings (show total count)
        if (allFindings.length > 15) {
          if (yPos + 15 > contentBottom) {
            doc.addPage();
            yPos = headerHeight + 15;
          }
          
          doc.setFontSize(8);
          doc.setFont('helvetica', 'italic');
          doc.setTextColor(120, 120, 120);
          doc.text(`... and ${allFindings.length - 15} more finding${allFindings.length - 15 === 1 ? '' : 's'} (see table above for complete list)`, margin + 8, yPos);
          yPos += 15;
        }
      }
    }
  } else {
    // No findings
    doc.setFillColor(240, 253, 244);
    doc.roundedRect(margin, yPos, contentWidth, 30, 3, 3, 'F');
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(34, 197, 94);
    doc.text('✓ No security issues found!', margin + 10, yPos + 18);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(100, 100, 100);
    doc.text('All scanned files follow security best practices.', margin + 10, yPos + 25);
  }
  
  // Header and Footer on all pages (same as single file)
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    
    // Header
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, headerHeight, 'F');
    
    doc.setFontSize(18);
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.text('Repository Security Scan Report', pageWidth / 2, 15, { align: 'center' });
    
    doc.setFontSize(8);
    doc.setTextColor(200, 200, 200);
    doc.setFont('helvetica', 'normal');
    const subtitleText1 = 'IAC Security Scanner on ';
    const linkText = 'peachycloudsecurity.com';
    const subtitleText2 = ' (theshukladuo)';
    const subtitle1Width = doc.getTextWidth(subtitleText1);
    const linkWidth = doc.getTextWidth(linkText);
    const subtitle2Width = doc.getTextWidth(subtitleText2);
    const totalWidth = subtitle1Width + linkWidth + subtitle2Width;
    const subtitleX = (pageWidth - totalWidth) / 2;
    
    doc.text(subtitleText1, subtitleX, 23);
    doc.setTextColor(100, 180, 255);
    doc.text(linkText, subtitleX + subtitle1Width, 23);
    doc.link(subtitleX + subtitle1Width, 20, linkWidth, 3, { url: 'https://peachycloudsecurity.com' });
    doc.setTextColor(200, 200, 200);
    doc.text(subtitleText2, subtitleX + subtitle1Width + linkWidth, 23);
    
    // Header links
    doc.setFontSize(7);
    doc.setTextColor(180, 180, 180);
    doc.setFont('helvetica', 'normal');
    
    const headerLinks = [
      { text: 'Peachycloud Security', url: 'https://peachycloudsecurity.com' },
      { text: 'Book Session', url: SITE.links.topmate },
      { text: 'Buy me a coffee', url: SITE.links.kofi },
      { text: 'Subscribe Youtube ', url: SITE.youtube.subscribeUrl },
      { text: 'GitHub', url: 'https://github.com/peachycloudsecurity/iac-security-scanner' }
    ];
    
    const totalLinksWidth = headerLinks.reduce((sum, link) => sum + doc.getTextWidth(link.text), 0);
    const separatorsWidth = (headerLinks.length - 1) * doc.getTextWidth(' | ');
    const linksStartX = (pageWidth - (totalLinksWidth + separatorsWidth)) / 2;
    
    let headerLinkX = linksStartX;
    const headerLinkY = 30;
    
    for (let j = 0; j < headerLinks.length; j++) {
      const link = headerLinks[j];
      doc.setTextColor(180, 180, 180);
      doc.text(link.text, headerLinkX, headerLinkY);
      doc.link(headerLinkX, headerLinkY - 2, doc.getTextWidth(link.text), 3, { url: link.url });
      headerLinkX += doc.getTextWidth(link.text);
      
      if (j < headerLinks.length - 1) {
        doc.setTextColor(120, 120, 120);
        doc.text(' | ', headerLinkX, headerLinkY);
        headerLinkX += doc.getTextWidth(' | ');
      }
    }
    
    // Footer (same as single file)
    const pageInfoY = pageHeight - 5;
    const pageInfoHeight = 5;
    
    doc.setFontSize(6);
    doc.setTextColor(100, 100, 100);
    const wrappedDisclaimer = doc.splitTextToSize(SITE.disclaimer, contentWidth);
    const disclaimerHeight = wrappedDisclaimer.length * 3.5;
    const disclaimerY = pageInfoY - pageInfoHeight - disclaimerHeight - 3;
    
    const linkY = disclaimerY - 8;
    const footerY = linkY - 5;
    
    doc.setDrawColor(220, 220, 220);
    doc.setLineWidth(0.5);
    doc.line(margin, footerY, pageWidth - margin, footerY);
    
    doc.setFontSize(7);
    doc.setTextColor(120, 120, 120);
    doc.setFont('helvetica', 'normal');
    
    let footerX = margin;
    const linkSpacing = 8;
    
    doc.setTextColor(100, 180, 255);
    doc.text('Peachycloud Security', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('Peachycloud Security'), 4, { url: 'https://peachycloudsecurity.com' });
    footerX += doc.getTextWidth('Peachycloud Security') + linkSpacing;
    
    doc.setTextColor(120, 120, 120);
    doc.text('|', footerX, linkY);
    footerX += 5;
    
    doc.setTextColor(100, 180, 255);
    doc.text('Book Session', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('Book Session'), 4, { url: SITE.links.topmate });
    footerX += doc.getTextWidth('Book Session') + linkSpacing;
    
    doc.setTextColor(120, 120, 120);
    doc.text('|', footerX, linkY);
    footerX += 5;
    
    doc.setTextColor(100, 180, 255);
    doc.text('Buy me a coffee', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('Buy me a coffee'), 4, { url: SITE.links.kofi });
    footerX += doc.getTextWidth('Buy me a coffee') + linkSpacing;
    
    doc.setTextColor(120, 120, 120);
    doc.text('|', footerX, linkY);
    footerX += 5;
    
    doc.setTextColor(100, 180, 255);
    doc.text('Subscribe YouTube', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('Subscribe YouTube'), 4, { url: SITE.youtube.subscribeUrl });
    footerX += doc.getTextWidth('Subscribe Youtube') + linkSpacing;
    
    doc.setTextColor(120, 120, 120);
    doc.text('|', footerX, linkY);
    footerX += 5;
    
    doc.setTextColor(100, 180, 255);
    doc.text('GitHub', footerX, linkY);
    doc.link(footerX, linkY - 3, doc.getTextWidth('GitHub'), 4, { url: 'https://github.com/peachycloudsecurity/iac-security-scanner' });
    
    doc.setFontSize(6);
    doc.setTextColor(100, 100, 100);
    for (let j = 0; j < wrappedDisclaimer.length; j++) {
      doc.text(wrappedDisclaimer[j], margin, disclaimerY + (j * 3.5));
    }
    
    doc.setFontSize(7);
    doc.setTextColor(150, 150, 150);
    doc.text(
      `Page ${i} of ${pageCount} | All IAC scanner analysis runs locally in your browser by peachycloudsecurity`,
      pageWidth / 2,
      pageInfoY,
      { align: 'center' }
    );
  }
  
  // Download
  const dateStr = new Date().toISOString().split('T')[0];
  const timeStr = new Date().toTimeString().split(' ')[0].replace(/:/g, '-');
  doc.save(`repository-scan-${dateStr}-${timeStr}.pdf`);
}
