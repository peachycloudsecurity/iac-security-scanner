import React from 'react';
import { FileType } from '@/types/scanner';
import { getFileTypeLabel, getFileTypeIcon } from '@/utils/fileDetector';
import { cn } from '@/lib/utils';

interface FileTypeBadgeProps {
  fileType: FileType;
  className?: string;
}

export function FileTypeBadge({ fileType, className }: FileTypeBadgeProps) {
  return (
    <span className={cn('file-type-badge', className)}>
      <span className="text-base">{getFileTypeIcon(fileType)}</span>
      <span>{getFileTypeLabel(fileType)}</span>
    </span>
  );
}
