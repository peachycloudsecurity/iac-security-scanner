import React, { useState } from 'react';
import { FileCode, Search, ChevronRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';

export interface Example {
  id: string;
  name: string;
  description: string;
  category: 'terraform' | 'kubernetes' | 'dockerfile' | 'cloudformation' | 'docker-compose';
  content: string;
  fileName: string;
}

// Placeholder examples - will be replaced with actual samples
const exampleCategories = {
  terraform: [
    {
      id: 'tf-iam-privesc-multiple',
      name: 'IAM Privilege Escalation (Multiple Policies)',
      description: 'IAM policies that allow privilege escalation when combined - ec2:RunInstances + iam:PassRole',
      category: 'terraform' as const,
      content: `############################################
# Policy 1: EC2 launch capability (partial)
############################################
resource "aws_iam_policy" "lab_ec2_launcher" {
  name        = "lab-ec2-launcher"
  path        = "/"
  description = "Allows EC2 actions required to launch instances, without iam:PassRole"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:RunInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

############################################
# Policy 2: PassRole on all roles
############################################
resource "aws_iam_policy" "lab_passrole_any" {
  name        = "lab-passrole-any"
  path        = "/"
  description = "Allows iam:PassRole on all roles"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "*"
      }
    ]
  })
}

############################################
# IAM Role (target for escalation)
############################################
resource "aws_iam_role" "lab_target_role" {
  name = "lab-privesc-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          AWS = var.assume_role_principal
        }
      }
    ]
  })
}

############################################
# IAM User (attacker identity)
############################################
resource "aws_iam_user" "lab_attacker_user" {
  name = "lab-privesc-user"
  path = "/"
}

resource "aws_iam_access_key" "lab_attacker_user_key" {
  user = aws_iam_user.lab_attacker_user.name
}

############################################
# Attach BOTH policies to USER
############################################
resource "aws_iam_user_policy_attachment" "user_attach_ec2" {
  user       = aws_iam_user.lab_attacker_user.name
  policy_arn = aws_iam_policy.lab_ec2_launcher.arn
}

resource "aws_iam_user_policy_attachment" "user_attach_passrole" {
  user       = aws_iam_user.lab_attacker_user.name
  policy_arn = aws_iam_policy.lab_passrole_any.arn
}

############################################
# Attach BOTH policies to ROLE
############################################
resource "aws_iam_role_policy_attachment" "role_attach_ec2" {
  role       = aws_iam_role.lab_target_role.name
  policy_arn = aws_iam_policy.lab_ec2_launcher.arn
}

resource "aws_iam_role_policy_attachment" "role_attach_passrole" {
  role       = aws_iam_role.lab_target_role.name
  policy_arn = aws_iam_policy.lab_passrole_any.arn
}`,
      fileName: 'example-iam-privesc.tf',
    },
    {
      id: 'tf-s3-public',
      name: 'S3 Bucket Public Access',
      description: 'Example Terraform configuration with S3 bucket that allows public access',
      category: 'terraform' as const,
      content: '# Placeholder: S3 bucket with public access\nresource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n}\n\nresource "aws_s3_bucket_public_access_block" "example" {\n  bucket = aws_s3_bucket.example.id\n  \n  block_public_acls       = false\n  block_public_policy     = false\n  ignore_public_acls      = false\n  restrict_public_buckets = false\n}',
      fileName: 'main.tf',
    },
    {
      id: 'tf-rds-encryption',
      name: 'RDS Without Encryption',
      description: 'RDS instance configuration missing encryption',
      category: 'terraform' as const,
      content: '# Placeholder: RDS instance without encryption\nresource "aws_db_instance" "example" {\n  identifier = "example-db"\n  engine     = "mysql"\n  instance_class = "db.t3.micro"\n  allocated_storage = 20\n  \n  # Missing storage_encrypted = true\n}',
      fileName: 'rds.tf',
    },
  ],
  kubernetes: [
    {
      id: 'k8s-insecure-deployment',
      name: 'Insecure Deployment with Multiple Vulnerabilities',
      description: 'Kubernetes Deployment with privileged mode, root user, missing resource limits, host network, dangerous capabilities, and host path volumes',
      category: 'kubernetes' as const,
      content: `# INTENTIONALLY INSECURE: Multiple Security Vulnerabilities
# DO NOT USE IN PRODUCTION

apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
  namespace: default  # Using default namespace
spec:
  replicas: 2
  selector:
    matchLabels:
      app: insecure-app
  template:
    metadata:
      labels:
        app: insecure-app
    spec:
      # Host network bypasses Kubernetes network isolation
      hostNetwork: true
      hostPID: true      # Shares host process namespace
      hostIPC: true      # Shares host IPC namespace
      
      containers:
      - name: web
        # Using latest tag - non-reproducible
        image: nginx:latest
        imagePullPolicy: IfNotPresent  # Should be Always
        
        # Running as root user
        securityContext:
          privileged: true              # Full host access
          allowPrivilegeEscalation: true # Allows privilege escalation
          runAsUser: 0                 # Root user (UID 0)
          runAsNonRoot: false
          readOnlyRootFilesystem: false # Writable filesystem
          
          # Dangerous capabilities
          capabilities:
            add:
              - SYS_ADMIN              # Can modify host
              - NET_ADMIN              # Can modify network
              - NET_RAW                # Raw sockets
              - ALL                    # All capabilities
            # Missing drop: ["ALL"]
        
        # No resource limits - can exhaust node resources
        # resources:
        #   limits:
        #     cpu: "500m"
        #     memory: "512Mi"
        
        # Secrets as environment variables (insecure)
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        
        # Host path volume mount
        volumeMounts:
        - name: host-root
          mountPath: /host
        - name: docker-sock
          mountPath: /var/run/docker.sock
      
      volumes:
      - name: host-root
        hostPath:
          path: /                    # Mounts entire host filesystem
          type: Directory
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock # Docker socket access
          type: Socket

---
# Service exposing the insecure deployment
apiVersion: v1
kind: Service
metadata:
  name: insecure-app-service
  namespace: default
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 80
  selector:
    app: insecure-app`,
      fileName: 'insecure-deployment.yaml',
    },
    {
      id: 'k8s-statefulset-vulnerable',
      name: 'Vulnerable StatefulSet Configuration',
      description: 'StatefulSet with missing security contexts, resource limits, and using default namespace',
      category: 'kubernetes' as const,
      content: `# Vulnerable StatefulSet - Missing Security Controls
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: vulnerable-db
  namespace: default  # Should use dedicated namespace
spec:
  serviceName: "db"
  replicas: 3
  selector:
    matchLabels:
      app: database
  template:
    metadata:
      labels:
        app: database
    spec:
      containers:
      - name: postgres
        # No version tag specified
        image: postgres
        imagePullPolicy: IfNotPresent
        
        # No securityContext defined
        # Will run as root by default
        # No read-only filesystem
        # Allows privilege escalation by default
        
        # Missing resource limits
        # No CPU or memory constraints
        
        # Secrets via environment variables
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        - name: POSTGRES_USER
          value: admin  # Default username
        
        ports:
        - containerPort: 5432
          name: postgres
      
      # No service account specified
      # No network policies
      # No pod security policies`,
      fileName: 'vulnerable-statefulset.yaml',
    },
  ],
  dockerfile: [
    {
      id: 'docker-insecure-multi',
      name: 'Insecure Dockerfile with Multiple Vulnerabilities',
      description: 'Dockerfile with root user, latest tags, missing HEALTHCHECK, dangerous RUN commands, and no multi-stage build',
      category: 'dockerfile' as const,
      content: `# INTENTIONALLY INSECURE: Multiple Security Vulnerabilities
# DO NOT USE IN PRODUCTION

# Using latest tag - non-reproducible builds
FROM ubuntu:latest

# Running as root (no USER directive)
# Container will execute as UID 0 with full privileges

# Dangerous installation method - curl | sh
RUN curl -fsSL https://get.docker.com | sh

# Using apt-get upgrade - can introduce vulnerabilities
RUN apt-get update && apt-get upgrade -y

# Installing packages with pip --upgrade (unsafe)
RUN pip install --upgrade flask requests

# Installing global npm packages (can cause conflicts)
RUN npm install -g express-generator

# Hardcoded secrets in build (visible in image layers)
ENV DB_PASSWORD=admin123
ENV API_KEY=secret-key-12345
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

# Using ADD instead of COPY (less transparent)
ADD https://example.com/script.sh /tmp/script.sh

# Missing EXPOSE instruction (ports not documented)
# Application listens on port 8080 but not declared

# Missing HEALTHCHECK instruction
# Cannot detect container failures

# Single-stage build includes build tools in final image
RUN apt-get install -y gcc make build-essential python3-dev
RUN npm install
RUN pip install -r requirements.txt

# Application code
COPY . /app
WORKDIR /app

# Still running as root
CMD ["python3", "app.py"]`,
      fileName: 'Dockerfile',
    },
    {
      id: 'docker-node-vulnerable',
      name: 'Vulnerable Node.js Dockerfile',
      description: 'Node.js Dockerfile with root user, latest tag, missing HEALTHCHECK, and dangerous npm install',
      category: 'dockerfile' as const,
      content: `# Vulnerable Node.js Dockerfile
FROM node:latest

# No USER directive - runs as root
# Latest tag - non-reproducible

# Dangerous: Installing global packages
RUN npm install -g pm2 nodemon

# Using ADD with URL (less secure than COPY)
ADD https://raw.githubusercontent.com/example/install.sh /tmp/install.sh
RUN chmod +x /tmp/install.sh && /tmp/install.sh

# Hardcoded environment variables with secrets
ENV NODE_ENV=production
ENV DATABASE_URL=postgres://admin:password123@db:5432/mydb
ENV JWT_SECRET=my-super-secret-jwt-key-12345

# Missing EXPOSE for port 3000
# Missing HEALTHCHECK

WORKDIR /app

# Installing dependencies (should be in separate stage)
RUN npm install

COPY . .

# Still root user
CMD ["node", "server.js"]`,
      fileName: 'Dockerfile.node',
    },
    {
      id: 'docker-python-insecure',
      name: 'Insecure Python Dockerfile',
      description: 'Python Dockerfile with root user, pip --upgrade, missing HEALTHCHECK, and no multi-stage build',
      category: 'dockerfile' as const,
      content: `# Insecure Python Application Dockerfile
FROM python:latest

# Root user by default
# Latest tag

# Dangerous: pip install --upgrade
RUN pip install --upgrade pip setuptools wheel

# Installing build tools (should be in builder stage)
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    make \\
    libffi-dev \\
    python3-dev

# Hardcoded secrets
ENV SECRET_KEY=django-insecure-key-12345
ENV DATABASE_PASSWORD=postgres-password-123

# Using sudo unnecessarily
RUN sudo apt-get install -y curl

# Dangerous: Downloading and executing script
RUN curl -sSL https://bootstrap.pypa.io/get-pip.py | python

# Missing EXPOSE for port 8000
# Missing HEALTHCHECK

WORKDIR /app

# Installing all dependencies (including dev dependencies)
RUN pip install -r requirements.txt

COPY . .

# Running as root
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app.wsgi:application"]`,
      fileName: 'Dockerfile.python',
    },
  ],
  cloudformation: [
    {
      id: 'cfn-insecure-rds',
      name: 'Insecure RDS Database with Multiple Vulnerabilities',
      description: 'CloudFormation template with public RDS, hardcoded credentials, open security groups, and sensitive outputs',
      category: 'cloudformation' as const,
      content: `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "INTENTIONALLY INSECURE: Public RDS with hardcoded credentials and open network access. DO NOT USE IN PRODUCTION.",
  "Resources": {
    "OpenDatabaseSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Open MySQL access to the world",
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "CidrIp": "0.0.0.0/0"
          }
        ]
      }
    },
    "InsecureMasterDB": {
      "Type": "AWS::RDS::DBInstance",
      "DeletionPolicy": "Delete",
      "Properties": {
        "DBInstanceIdentifier": "lab-insecure-db",
        "AllocatedStorage": 5,
        "DBInstanceClass": "db.t3.micro",
        "Engine": "MySQL",
        "MasterUsername": "admin",
        "MasterUserPassword": "Password123!",
        "PubliclyAccessible": true,
        "BackupRetentionPeriod": 0,
        "StorageEncrypted": false,
        "DeletionProtection": false,
        "VPCSecurityGroups": [
          { "Fn::GetAtt": ["OpenDatabaseSecurityGroup", "GroupId"] }
        ],
        "Tags": [
          {
            "Key": "Purpose",
            "Value": "InsecureLab"
          }
        ]
      }
    },
    "InsecureReplicaDB": {
      "Type": "AWS::RDS::DBInstance",
      "DeletionPolicy": "Retain",
      "Properties": {
        "SourceDBInstanceIdentifier": { "Ref": "InsecureMasterDB" },
        "DBInstanceClass": "db.t3.micro",
        "PubliclyAccessible": true,
        "StorageEncrypted": false,
        "Tags": [
          {
            "Key": "Purpose",
            "Value": "InsecureReplica"
          }
        ]
      }
    }
  },
  "Outputs": {
    "DatabaseEndpoint": {
      "Description": "Public database endpoint",
      "Value": {
        "Fn::GetAtt": ["InsecureMasterDB", "Endpoint.Address"]
      }
    },
    "DatabasePort": {
      "Value": {
        "Fn::GetAtt": ["InsecureMasterDB", "Endpoint.Port"]
      }
    },
    "DatabaseUsername": {
      "Value": "admin"
    },
    "DatabasePassword": {
      "Value": "Password123!"
    }
  }
}`,
      fileName: 'template.json',
    },
  ],
  'docker-compose': [
    {
      id: 'compose-vulnerable-app',
      name: 'Vulnerable Multi-Service Application',
      description: 'Docker Compose with multiple security vulnerabilities - privileged mode, secrets, host mounts, public ports',
      category: 'docker-compose' as const,
      content: `# Vulnerable Docker Compose - Multiple Security Issues
version: "3.8"

services:
  # Web application with multiple vulnerabilities
  web:
    image: nginx:latest  # Using latest tag
    privileged: true     # Privileged mode enabled
    network_mode: host   # Using host network
    user: root          # Running as root
    restart: always     # Always restart policy
    
    # Dangerous volume mounts
    volumes:
      - /:/host-root      # Mount entire host filesystem
      - /var/run/docker.sock:/var/run/docker.sock  # Docker socket access
      - /etc/passwd:/etc/passwd:ro  # Host password file
    
    # Exposed to all interfaces
    ports:
      - "80:80"          # Bound to all interfaces
      - "443:443"
    
    # Hardcoded secrets in environment
    environment:
      - DB_PASSWORD=admin123
      - AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
      - AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      - API_TOKEN=secret-token-12345
    
    # Dangerous capabilities
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
      - ALL
    
    # Insecure security options
    security_opt:
      - no-new-privileges:false
      - apparmor:unconfined
      - seccomp:unconfined
    
    # Host device access
    devices:
      - "/dev/sda:/dev/sda"
    
    # Host PID access
    pid: host

  # Database service with issues  
  database:
    image: postgres        # No version tag
    user: "0"             # Root user (UID 0)
    
    # More environment secrets
    environment:
      POSTGRES_PASSWORD: "hardcoded-password-123"
      POSTGRES_USER: admin
    
    # No resource limits defined
    # No read-only filesystem
    
    volumes:
      - /var/lib/postgresql:/var/lib/postgresql/data  # Host mount

# No custom networks defined - using default bridge`,
      fileName: 'vulnerable-app.yaml',
    },
  ],
};

interface ExamplesPanelProps {
  onSelectExample: (example: Example) => void;
  className?: string;
}

export function ExamplesPanel({ onSelectExample, className }: ExamplesPanelProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [isExpanded, setIsExpanded] = useState(false);

  const allExamples: Example[] = Object.values(exampleCategories).flat();

  const filteredExamples = allExamples.filter(example => {
    const matchesSearch = 
      example.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      example.description.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesCategory = selectedCategory === 'all' || example.category === selectedCategory;
    
    return matchesSearch && matchesCategory;
  });

  const categoryCounts = {
    all: allExamples.length,
    terraform: exampleCategories.terraform.length,
    kubernetes: exampleCategories.kubernetes.length,
    dockerfile: exampleCategories.dockerfile.length,
    cloudformation: exampleCategories.cloudformation.length,
    'docker-compose': exampleCategories['docker-compose'].length,
  };

  return (
    <div className={cn("space-y-4", className)}>
      <div className="space-y-2">
        <label className="text-sm font-medium">Examples</label>
        <div className="relative min-h-[200px] bg-code-bg border border-border rounded-lg p-4 space-y-3">
          <p className="text-xs text-muted-foreground">
          Select an example to test the scanner with common security issues
        </p>
        
        {/* Search */}
          <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Search examples..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 bg-background"
          />
        </div>

          {/* Category Tabs - Compact */}
        <Tabs value={selectedCategory} onValueChange={setSelectedCategory} className="w-full">
            <TabsList className="grid w-full grid-cols-6 h-7">
              <TabsTrigger value="all" className="text-xs px-1 h-6">
              All ({categoryCounts.all})
            </TabsTrigger>
              <TabsTrigger value="terraform" className="text-xs px-1 h-6">
              TF ({categoryCounts.terraform})
            </TabsTrigger>
              <TabsTrigger value="kubernetes" className="text-xs px-1 h-6">
              K8s ({categoryCounts.kubernetes})
            </TabsTrigger>
              <TabsTrigger value="dockerfile" className="text-xs px-1 h-6">
              Docker ({categoryCounts.dockerfile})
            </TabsTrigger>
              <TabsTrigger value="cloudformation" className="text-xs px-1 h-6">
              CFN ({categoryCounts.cloudformation})
            </TabsTrigger>
              <TabsTrigger value="docker-compose" className="text-xs px-1 h-6">
              Compose ({categoryCounts['docker-compose']})
            </TabsTrigger>
          </TabsList>

            {/* Examples List - Compact to fit in box */}
            <div className={`space-y-1 overflow-y-auto mt-2 ${isExpanded ? 'max-h-[180px]' : 'max-h-[90px]'}`}>
            {filteredExamples.length === 0 ? (
              <div className="text-center py-2 text-muted-foreground">
                <FileCode className="h-6 w-6 mx-auto mb-1 opacity-50" />
                <p className="text-xs">No examples found</p>
              </div>
            ) : (
              (isExpanded ? filteredExamples : filteredExamples.slice(0, 2)).map((example) => (
                <div
                  key={example.id}
                  className="border border-border rounded p-2 hover:bg-muted/50 transition-colors cursor-pointer group"
                  onClick={() => onSelectExample(example)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <FileCode className="h-3 w-3 text-primary flex-shrink-0" />
                        <h4 className="font-medium text-foreground text-xs truncate">
                          {example.name}
                        </h4>
                      </div>
                      <p className="text-xs text-muted-foreground truncate">
                        {example.description}
                      </p>
                      <span className="text-xs px-1 py-0.5 bg-primary/10 text-primary rounded text-[10px]">
                          {example.fileName}
                        </span>
                    </div>
                    <ChevronRight className="h-3 w-3 text-muted-foreground group-hover:text-primary transition-colors flex-shrink-0" />
                  </div>
                </div>
              ))
            )}
            {!isExpanded && filteredExamples.length > 2 && (
              <div className="text-center">
                <button 
                  onClick={() => setIsExpanded(true)}
                  className="text-xs text-primary hover:text-primary/80 cursor-pointer transition-colors"
                >
                  ... and {filteredExamples.length - 2} more examples (click to expand)
                </button>
              </div>
            )}
            {isExpanded && (
              <div className="text-center">
                <button 
                  onClick={() => setIsExpanded(false)}
                  className="text-xs text-primary hover:text-primary/80 cursor-pointer transition-colors"
                >
                  Show less
                </button>
              </div>
            )}
          </div>
        </Tabs>
        </div>
      </div>
    </div>
  );
}
