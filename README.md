# IaC Security Scanner

Browser-based Infrastructure as Code security scanner. Analyzes Terraform, Kubernetes, Docker, and CloudFormation files directly in your browser. No server, no uploads, everything runs client-side.

## Features

- 150+ security rules covering common misconfigurations
- Supports Terraform, Kubernetes, Docker, CloudFormation
- GitHub repository scanning with rate limit handling
- PDF report export
- Single file HTML output for easy deployment

## Quick Start

### Prerequisites

Node.js 18+ and npm

### Installation

```bash
git clone https://github.com/yourusername/iac-security-scanner.git
cd iac-security-scanner
npm install
```

### Development

```bash
npm run dev
```

Opens at `http://localhost:5173`

### Build

```bash
npm run build
```

Builds a single `index.html` file in the `docs/` folder. Open `docs/index.html` in your browser to use the scanner.

The build bundles all CSS and JavaScript inline into one HTML file using vite-plugin-singlefile.

### Deployment

Upload `docs/index.html` to any static hosting service. Works with GitHub Pages, Netlify, Vercel, or any web server.

For GitHub Pages, enable Pages in repository settings and point to the `docs` folder. The included GitHub Actions workflow automatically builds on push to main branch.

## Usage

1. Upload a file or paste code
2. Enter a GitHub repository URL to scan entire repos
3. Review findings with severity ratings
4. Export PDF reports

## Supported File Types

- Terraform: `.tf`, `.tfvars`, `.hcl`
- Kubernetes: `.yaml`, `.yml`
- Docker: `Dockerfile`, `docker-compose.yml`
- CloudFormation: `.template`, `.json`, `.yaml`, `.yml`

## GitHub Repository Scanning

Scan public GitHub repositories by entering the repository URL. The scanner handles rate limiting automatically with 200ms delays between requests. Unauthenticated GitHub API limit is 60 requests per hour.

## Project Structure

```
src/
├── components/     # React components
├── rules/          # 2448 security rules by IaC type
├── parsers/        # File parsers for each format
├── engine/         # Core scanning logic
└── utils/          # GitHub client, PDF export, etc.
```

## Build Scripts

- `npm run dev` - Development server
- `npm run build` - Production build to `docs/` folder
- `npm run preview` - Preview production build locally
- `npm run lint` - Run ESLint

## Technical Details

- Client-side only, no server required
- Single file HTML output for production
- Security rules based on Checkov and tfsec
- Custom parsers for each IaC format
- PDF generation with jsPDF

## Troubleshooting

**No findings detected**: Check file format is supported and syntax is valid.

**GitHub scanning errors**: Rate limit (403) or private repository (404). Wait a few minutes and retry.

**Large repositories**: May take several minutes. Progress is shown during scanning.

## Credits

Security rules inspired by:
- Checkov (bridgecrewio/checkov)
- tfsec (aquasecurity/tfsec)
- GitHub scanning functionality from sbomplay (cyfinoid/sbomplay)

## License

GPL-3.0. See LICENSE file for details.

## Disclaimer

This tool is designed for security auditing and analysis of Infrastructure as Code configurations you own or have explicit permission to analyze. Always ensure you have proper authorization before scanning repositories or configurations you don't own. The authors are not responsible for any misuse of this software.

This website, apps, scanner and results are provided strictly for educational purposes, independently authored and not endorsed by the author's employers or any corporate entity, provided without warranties or guarantees, with no liability accepted for misuse or misapplication.

## Peachycloud Security

Hands-On Multi-Cloud & Cloud-Native Security Education

Created by The Shukla Duo (Anjali & Divyanshu), this tool is part of our mission to make cloud security accessible through practical, hands-on learning. We specialize in AWS, GCP, Kubernetes security, and DevSecOps practices.

### Learn & Grow

Explore our educational content and training programs:

[YouTube Channel](https://www.youtube.com/@peachycloudsecurity) | [Website](https://peachycloudsecurity.com) | [1:1 Consultations](https://topmate.io/peachycloudsecurity)

Learn cloud security through hands-on labs, real-world scenarios, and practical tutorials covering GCP & AWS, GKE & EKS, Kubernetes, Containers, DevSecOps, and Threat Modeling.

### Support Our Work

If this tool helps you secure your infrastructure, consider supporting our educational mission:

[Sponsor on GitHub](https://github.com/sponsors/peachycloudsecurity)

Your support helps us create more free educational content and security tools for the community.
