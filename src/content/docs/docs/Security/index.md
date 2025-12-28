---
date: '2025-12-28'
title: 'Security'
description: 'Security guidelines and threat models for Fabric.js applications'
sidebar:
  label: 'Security Overview'
  order: 700
---

# Security

This section contains security guidelines, threat models, and best practices for building secure applications with Fabric.js.

## Overview

Fabric.js is a powerful canvas library that handles user input, serialization/deserialization, and rendering. Like any web application that processes user-generated content, applications using Fabric.js need to be designed with security in mind.

## Key Security Concerns

### Cross-Site Scripting (XSS)
Canvas libraries that support loading data from external sources (SVG, JSON) are potential vectors for XSS attacks. Proper input validation and output encoding are essential.

### Data Integrity
When serializing and deserializing canvas state, ensure that the data hasn't been tampered with and comes from trusted sources.

### Browser API Access
Modern browsers provide powerful local capabilities (File System Access, Clipboard, Geolocation, etc.). When combined with XSS vulnerabilities, these can lead to severe security breaches.

## Documents in This Section

- **[Threat Model: XSS + Local Capabilities](./threat-model-xss-local-capabilities)** - Comprehensive threat modeling for combined web XSS and local capability risks

## Quick Security Checklist

When building applications with Fabric.js:

- [ ] Validate all SVG/JSON input before loading
- [ ] Use `fabric.util.string.escapeXml()` for user-provided text
- [ ] Implement Content Security Policy (CSP)
- [ ] Validate image sources against an allowlist
- [ ] Never use `eval()` or `Function()` with user input
- [ ] Sanitize custom object properties
- [ ] Implement server-side validation
- [ ] Use Permission Policies to restrict browser APIs
- [ ] Regular security audits of canvas data handling
- [ ] Keep Fabric.js updated to the latest version

## Reporting Security Issues

If you discover a security vulnerability in Fabric.js, please report it responsibly:

1. **Do not** open a public issue
2. Email the security details to the Fabric.js maintainers
3. Allow time for the vulnerability to be patched before public disclosure

For this documentation site or implementation-specific issues in your application, follow your organization's security incident response procedures.

## Additional Resources

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [MDN Web Security Documentation](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Fabric.js GitHub Repository](https://github.com/fabricjs/fabric.js)
- [Fabric.js Security Utilities](/api/fabric/namespaces/util/namespaces/string/)

## Stay Informed

Security is an evolving field. Stay updated with:
- Fabric.js release notes for security patches
- OWASP security advisories
- Browser security announcements
- Web security newsletters and blogs

---

Last updated: 2025-12-28
