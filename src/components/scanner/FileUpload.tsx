import React, { useState, useCallback } from 'react';
import { Upload, FileCode, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

interface FileUploadProps {
  onFileSelect: (fileName: string, content: string) => void;
  disabled?: boolean;
}

export function FileUpload({ onFileSelect, disabled }: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) setIsDragging(true);
  }, [disabled]);
  
  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);
  
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    if (disabled) return;
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      processFile(files[0]);
    }
  }, [disabled]);
  
  const processFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setSelectedFile(file.name);
      onFileSelect(file.name, content);
    };
    reader.readAsText(file);
  };
  
  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      processFile(files[0]);
    }
  };
  
  const clearFile = () => {
    setSelectedFile(null);
  };
  
  return (
    <div
      className={cn(
        'drop-zone p-6 text-center transition-all duration-200',
        isDragging && 'drop-zone-active',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <input
        type="file"
        id="file-input"
        className="hidden"
        onChange={handleFileInput}
        accept=".tf,.hcl,.json,.yaml,.yml,Dockerfile,.dockerfile"
        disabled={disabled}
      />
      
      {selectedFile ? (
        <div className="flex items-center justify-center gap-3">
          <FileCode className="w-5 h-5 text-primary" />
          <span className="font-mono text-sm text-foreground">{selectedFile}</span>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={clearFile}
            disabled={disabled}
          >
            <X className="w-4 h-4" />
          </Button>
        </div>
      ) : (
        <>
          <Upload className={cn(
            'w-10 h-10 mx-auto mb-3 transition-colors',
            isDragging ? 'text-primary' : 'text-muted-foreground'
          )} />
          <p className="text-sm text-foreground mb-1">
            Drag and drop your file here
          </p>
          <p className="text-xs text-muted-foreground mb-6">
            Supports: Terraform (.tf), CloudFormation (.json/.yaml), Kubernetes (.yaml/.yml), Dockerfile, Docker Compose (.yml/.yaml)
          </p>
          <div style={{ height: '8px' }}></div>
          <label htmlFor="file-input">
            <Button
              variant="outline"
              size="sm"
              className="cursor-pointer"
              disabled={disabled}
              asChild
            >
              <span>Browse Files</span>
            </Button>
          </label>
        </>
      )}
    </div>
  );
}
