# IaC Security Scanner

## About

A client-side Infrastructure as Code security scanner that analyzes Terraform, Kubernetes, Docker, and CloudFormation configurations directly in your browser. Built for security professionals, DevSecOps engineers, and cloud architects to identify security misconfigurations and compliance violations in real-time.

The tool features comprehensive IaC analysis including 200+ security rules, GitHub repository scanning, PDF reporting, and detailed remediation guidance. All analysis happens directly in your browser - no data ever leaves your machine.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-IaC%20Scanner-blue?style=for-the-badge&logo=github)](https://peachycloudsecurity.com/apps/scanner)

## Features

- **Multi-Format Support**: Terraform, Kubernetes, Docker, CloudFormation
- **200+ Security Rules**: Comprehensive coverage of common misconfigurations
- **GitHub Integration**: Scan entire repositories with rate limiting and progress tracking
- **Client-Side Processing**: Everything runs in your browser, no data uploads
- **PDF Export**: Professional scan reports with detailed findings and remediation steps
- **Real-Time Analysis**: Instant feedback as you paste or upload files
- **Example Library**: Built-in examples to test scanner capabilities
- **Privacy-First**: No accounts, no tracking, no data collection

## Quick Start

1. **Development Setup**:
   ```bash
   npm install
   npm run dev
   ```

2. **Open in Browser**: Navigate to `http://localhost:8080`

3. **Start Scanning**:
   - **Upload File**: Drag and drop your IaC files
   - **Paste Code**: Copy-paste configuration directly
   - **GitHub Repository**: Enter a public GitHub repo URL
   - **Examples**: Try built-in vulnerable examples

4. **Review Results**: Get detailed findings with severity ratings and remediation steps

5. **Export Report**: Download comprehensive PDF reports

## Supported File Types

- **Terraform**: `.tf`, `.tfvars`, `.hcl`
- **Kubernetes**: `.yaml`, `.yml` manifests
- **Docker**: `Dockerfile`, `docker-compose.yml`
- **CloudFormation**: `.template`, `.json`, `.yaml`, `.yml`

## GitHub Repository Scanning

Scan entire GitHub repositories for IaC security issues:

- **Public Repositories**: Enter any `https://github.com/owner/repo` URL
- **Rate Limiting**: Automatic handling with smart retry logic
- **Progress Tracking**: Real-time progress with file-by-file status
- **Bulk Analysis**: Scan hundreds of files with aggregated results
- **Export Support**: Download comprehensive multi-file reports

### Rate Limits & Best Practices

- **GitHub API**: 60 requests/hour (unauthenticated)
- **Smart Delays**: Built-in 200ms delays between requests
- **Error Handling**: Distinguishes between rate limits and access denied
- **Progress Updates**: Clear status messages and wait times

## Technical Details

- **Client-Side**: Pure JavaScript, no server required
- **Security Rules**: Based on Checkov and tfsec implementations
- **File Detection**: Automatic IaC format detection
- **Parsing**: Custom parsers for each IaC format
- **Export**: PDF generation with jsPDF
- **Storage**: Browser localStorage for settings

## Browser Compatibility

- Modern browsers with ES6+ support
- Requires File API for drag-and-drop uploads
- LocalStorage for configuration persistence
- No external dependencies beyond CDN resources

## Development & Deployment

### Production Build
```bash
npm run build
npm run preview
```

### Project Structure
```
browser-iac-scanner/
├── index.html              # Main application
├── src/
│   ├── components/         # React components
│   │   └── scanner/        # Scanner-specific components
│   ├── rules/             # Security rules by IaC type
│   │   ├── terraform/     # Terraform security rules
│   │   ├── kubernetes/    # Kubernetes security rules
│   │   ├── dockerfile/    # Docker security rules
│   │   └── cloudformation/ # CloudFormation rules
│   ├── parsers/           # IaC file parsers
│   ├── utils/             # Utility functions
│   └── types/             # TypeScript definitions
├── public/                # Static assets
└── package.json           # Dependencies and scripts
```

## Troubleshooting

### Common Issues

**No Issues Found**
- Ensure file format is supported
- Check file syntax and structure
- Some rules may not apply to your specific configuration

**GitHub Scanning Errors**
- **403 Forbidden**: Rate limit hit or private repository
- **404 Not Found**: Repository doesn't exist or is private
- **Connection Errors**: Check internet connection

**Performance Issues**
- Large files (>1MB) may take longer to process
- GitHub repositories with 100+ files require patience
- Clear browser cache if experiencing slowdowns

## 💬 Community & Learning

### YouTube Channel
Learn cloud security with hands-on tutorials and walkthroughs:

**[Subscribe to @peachycloudsecurity](https://www.youtube.com/@peachycloudsecurity)**

### Website & Resources
Explore more security tools and educational content:

**[Visit peachycloudsecurity.com](https://peachycloudsecurity.com)**

### Personal Consultations
Book 1:1 sessions for personalized security guidance:

**[Book on Topmate](https://topmate.io/peachycloudsecurity)**

## Credits

This project builds upon excellent work from the security community:

- **[Checkov](https://github.com/bridgecrewio/checkov)** - Comprehensive IaC security rules
- **[tfsec](https://github.com/aquasecurity/tfsec)** - Terraform security best practices
- **[sbomplay](https://github.com/cyfinoid/sbomplay)** - Github repo scanning functionality

We didn't reinvent the wheel - this is a browser-based implementation created using lovable.dev and chatgpt to make IaC scanning accessible without CLI installations.

## 📄 License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

**What this means:**
- You can use, modify, and distribute this software
- You must include the original license and copyright notice
- If you modify and distribute, you must also use GPL-3.0 for your changes
- Source code must be made available when you distribute the software

See the [GPL-3.0 License](https://www.gnu.org/licenses/gpl-3.0.html) for full details.

## ⚠️ Disclaimer

This tool is designed for security auditing and analysis of Infrastructure as Code configurations you own or have explicit permission to analyze. Always ensure you have proper authorization before scanning repositories or configurations you don't own. The authors are not responsible for any misuse of this software.

This website, apps, scanner and results are provided strictly for educational purposes, independently authored and not endorsed by the author's employers or any corporate entity, provided without warranties or guarantees, with no liability accepted for misuse or misapplication.

## 🔒 Peachycloud Security

**Hands-On Multi-Cloud & Cloud-Native Security Education**

Created by **The Shukla Duo (Anjali & Divyanshu)**, this tool is part of our mission to make cloud security accessible through practical, hands-on learning. We specialize in AWS, GCP, Kubernetes security, and DevSecOps practices.

### 🎓 Learn & Grow

Explore our educational content and training programs:

**[YouTube Channel](https://www.youtube.com/@peachycloudsecurity)** | **[Website](https://peachycloudsecurity.com)** | **[1:1 Consultations](https://topmate.io/peachycloudsecurity)**

Learn cloud security through hands-on labs, real-world scenarios, and practical tutorials covering GCP & AWS, GKE & EKS, Kubernetes, Containers, DevSecOps, and Threat Modeling.

### 💖 Support Our Work

If this tool helps you secure your infrastructure, consider supporting our educational mission:

**[Sponsor on GitHub](https://github.com/sponsors/peachycloudsecurity)**

Your support helps us create more free educational content and security tools for the community.

---

* Learn Multi-Cloud & Cloud-Native Security, One Lesson at a Time.* 🛡️

© 2024-2025 Peachycloud Security - The Shukla Duo
