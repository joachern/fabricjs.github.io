---
title: 'Threat Model: XSS + Local Capabilities'
description: 'Security threat modeling for combined Web XSS and local capability risks in Fabric.js'
sidebar:
  label: 'XSS + Local Capabilities'
  order: 1
---

# Threat Model: Web XSS + Local Capabilities Combined Risks

## Executive Summary

This document provides a comprehensive threat model for security risks arising from the combination of Cross-Site Scripting (XSS) vulnerabilities and local browser capabilities in applications using Fabric.js. When XSS vulnerabilities are exploited in conjunction with modern browser APIs (File System Access, Clipboard, WebRTC, etc.), they can lead to significantly more severe security impacts than XSS alone.

## Scope

This threat model covers:
- XSS vulnerabilities specific to canvas-based applications using Fabric.js
- Attack chains combining XSS with local browser capabilities
- Data exfiltration and manipulation risks
- Privilege escalation through browser APIs

## Threat Actors

### External Attackers
- **Skill Level**: Low to High
- **Motivation**: Data theft, credential harvesting, malware distribution
- **Access**: No initial access, exploits XSS vulnerabilities

### Malicious Insiders
- **Skill Level**: Medium to High
- **Motivation**: Data theft, sabotage
- **Access**: May have partial system access

## Attack Vectors

### 1. SVG/JSON Deserialization XSS

**Description**: Fabric.js supports loading canvas state from JSON and SVG formats. Maliciously crafted JSON or SVG files can inject executable code.

**Attack Chain**:
1. Attacker crafts malicious SVG/JSON containing XSS payload
2. Application loads the malicious data via `loadFromJSON()` or `loadSVGFromString()`
3. XSS executes in the context of the web application
4. Attacker leverages local browser APIs for privilege escalation

**Example Vulnerable Pattern**:
```javascript
// VULNERABLE: Loading untrusted SVG without validation
fabric.loadSVGFromString(untrustedSVGData, function(objects) {
  canvas.add(...objects);
});

// VULNERABLE: Loading JSON from untrusted source
canvas.loadFromJSON(userProvidedJSON);
```

**Impact with Local Capabilities**:
- **File System Access API**: Read/write local files after gaining user consent through social engineering
- **Clipboard API**: Steal sensitive data copied to clipboard (passwords, API keys)
- **WebRTC**: Access camera/microphone for surveillance
- **IndexedDB**: Access cached credentials or session tokens

### 2. Text Object Script Injection

**Description**: Text objects in Fabric.js can contain user input that, if not properly sanitized, may execute when exported to SVG or HTML.

**Attack Chain**:
1. User creates text object with malicious content
2. Canvas is exported to SVG via `toSVG()`
3. SVG is rendered in a different context (e.g., email, report generation)
4. Script executes and accesses local capabilities

**Example Vulnerable Pattern**:
```javascript
// VULNERABLE: Creating text with unsanitized user input
const text = new fabric.Text(userInput, {
  fontFamily: userSelectedFont // Font names not validated
});

// Export includes malicious content
const svg = canvas.toSVG();
```

**Impact**: When the exported SVG is loaded in another context with elevated privileges, it can:
- Access service worker scope for persistent attacks
- Modify localStorage/sessionStorage across origins
- Trigger downloads of malicious files

### 3. Image Source Manipulation

**Description**: Loading images from untrusted URLs or data URIs can lead to SSRF (Server-Side Request Forgery) or XSS through SVG images.

**Attack Chain**:
1. Attacker provides malicious image URL or data URI
2. Application loads image via `fabric.Image.fromURL()`
3. If SVG image, embedded scripts execute
4. Access to local capabilities is obtained

**Example Vulnerable Pattern**:
```javascript
// VULNERABLE: Loading images from user-provided URLs
fabric.Image.fromURL(userProvidedURL, function(img) {
  canvas.add(img);
});

// VULNERABLE: SVG data URI with embedded script
const maliciousSVG = 'data:image/svg+xml,<svg><script>...</script></svg>';
```

**Impact with Local Capabilities**:
- **Geolocation API**: Track user location in real-time
- **Sensors API**: Access accelerometer, gyroscope for device fingerprinting
- **Credential Management API**: Phish for credentials with native-looking prompts

### 4. Custom Properties and Metadata Injection

**Description**: Fabric.js allows custom properties on objects. These can be exploited to inject malicious code that executes during serialization/deserialization.

**Attack Chain**:
1. Attacker sets custom properties with executable payloads
2. Canvas state is saved and later restored
3. Custom property deserialization triggers code execution
4. Local browser capabilities are exploited

**Example Vulnerable Pattern**:
```javascript
// VULNERABLE: Accepting arbitrary custom properties
const rect = new fabric.Rect({
  customProperty: userInput, // Not sanitized
  onLoad: userFunction // Function injection
});
```

### 5. Event Handler Injection

**Description**: If event handlers are stored in canvas state or loaded from external sources, malicious handlers can be injected.

**Attack Chain**:
1. Malicious event handlers added to objects
2. Events trigger handler execution (mouse:down, object:modified, etc.)
3. Handlers access browser APIs with user privileges

**Example Vulnerable Pattern**:
```javascript
// VULNERABLE: Dynamically adding event handlers from untrusted source
canvas.on(eventType, eval(userProvidedHandler));
```

## Combined Attack Scenarios

### Scenario 1: Data Exfiltration via Clipboard + IndexedDB

**Attack Flow**:
1. XSS payload injected via SVG deserialization
2. Monitor clipboard for sensitive data (passwords, tokens)
3. Access IndexedDB for cached authentication tokens
4. Exfiltrate combined data to attacker-controlled server

**Mitigation**:
- Implement Content Security Policy (CSP) with `script-src 'self'`
- Validate and sanitize all SVG/JSON input
- Use `fabric.util.string.escapeXml()` for text content
- Implement Subresource Integrity (SRI) for external resources

### Scenario 2: Persistent Backdoor via Service Worker

**Attack Flow**:
1. XSS executed through image source manipulation
2. Register malicious service worker
3. Intercept all network requests for persistent access
4. Use File System Access API to read local design files

**Mitigation**:
- Restrict service worker registration scope
- Implement strict CSP headers
- Validate all image sources against allowlist
- Use CORS policies to prevent cross-origin resource loading

### Scenario 3: Social Engineering + File System Access

**Attack Flow**:
1. XSS payload delivered via custom property injection
2. Display fake dialog requesting file system access
3. User grants permission thinking it's legitimate
4. Read sensitive local files (config files, credentials)
5. Exfiltrate data through WebSocket connection

**Mitigation**:
- Never request permissions without clear user action
- Display warnings before file system access
- Implement file type restrictions
- Use Permission Policy to restrict dangerous APIs

## Mitigation Strategies

### Input Validation and Sanitization

1. **SVG/JSON Input**:
```javascript
// SECURE: Validate JSON structure before loading
function loadSafeJSON(jsonData) {
  try {
    const parsed = JSON.parse(jsonData);
    // Validate structure matches expected schema
    if (!isValidCanvasSchema(parsed)) {
      throw new Error('Invalid canvas schema');
    }
    canvas.loadFromJSON(parsed);
  } catch (e) {
    console.error('Invalid JSON data', e);
  }
}
```

2. **Text Content**:
```javascript
// SECURE: Use built-in escaping utilities
import { escapeXml } from 'fabric/util/string';

const text = new fabric.Text(escapeXml(userInput), {
  fontFamily: validateFontName(userSelectedFont)
});
```

3. **Image Sources**:
```javascript
// SECURE: Allowlist image sources
function loadSafeImage(url) {
  const allowedOrigins = ['https://trusted-cdn.com', 'https://example.com'];
  const urlObj = new URL(url);
  
  if (!allowedOrigins.includes(urlObj.origin)) {
    throw new Error('Untrusted image source');
  }
  
  // Prevent data URIs completely or validate them strictly
  if (url.startsWith('data:')) {
    throw new Error('Data URIs not allowed');
  }
  
  fabric.Image.fromURL(url, function(img) {
    canvas.add(img);
  });
}
```

### Content Security Policy

Implement strict CSP headers:
```http
Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self'; 
  style-src 'self' 'unsafe-inline'; 
  img-src 'self' https://trusted-cdn.com; 
  connect-src 'self'; 
  frame-ancestors 'none';
  form-action 'self';
```

### Permission Policies

Restrict access to sensitive browser APIs:
```http
Permissions-Policy: 
  geolocation=(), 
  camera=(), 
  microphone=(), 
  payment=(), 
  usb=(),
  clipboard-read=(self),
  clipboard-write=(self)
```

### Subresource Integrity

For external dependencies:
```html
<script src="https://cdn.example.com/fabric.min.js" 
        integrity="sha384-..." 
        crossorigin="anonymous"></script>
```

### Server-Side Validation

Always validate on the server side:
```javascript
// Server-side validation example
function validateCanvasData(canvasJSON) {
  // Check object count limits
  if (canvasJSON.objects && canvasJSON.objects.length > MAX_OBJECTS) {
    throw new Error('Too many objects');
  }
  
  // Validate each object type
  for (const obj of canvasJSON.objects) {
    if (!ALLOWED_OBJECT_TYPES.includes(obj.type)) {
      throw new Error(`Invalid object type: ${obj.type}`);
    }
    
    // Validate properties don't contain scripts
    validateObjectProperties(obj);
  }
  
  return true;
}
```

## Security Best Practices

### 1. Principle of Least Privilege
- Only request browser permissions when absolutely necessary
- Limit scope of file system access to specific directories
- Use read-only access when write is not required

### 2. Defense in Depth
- Layer multiple security controls (CSP + input validation + output encoding)
- Don't rely on client-side security alone
- Implement server-side validation and sanitization

### 3. Secure Defaults
- Disable dangerous features by default
- Require explicit opt-in for sensitive operations
- Default to most restrictive permissions

### 4. Regular Security Audits
- Review canvas data before serialization
- Monitor for suspicious event handler registrations
- Log and alert on permission requests

### 5. User Education
- Inform users about risks of loading untrusted canvas files
- Display warnings when accessing local capabilities
- Provide clear security guidelines in documentation

## Detection and Monitoring

### Client-Side Monitoring
```javascript
// Monitor for suspicious activity
const securityMonitor = {
  logPermissionRequest(api, granted) {
    console.warn(`Permission requested: ${api}, granted: ${granted}`);
    // Send to security analytics
  },
  
  logExternalResource(url) {
    console.warn(`External resource loaded: ${url}`);
    // Validate against policy
  },
  
  detectAnomalousEvents() {
    // Monitor for unusual patterns
    // - Rapid permission requests
    // - Large data exports
    // - Suspicious clipboard access
  }
};
```

### Server-Side Logging
- Log all canvas data saves/loads
- Track permission grants
- Monitor for patterns of malicious activity

## Incident Response

### If XSS is Detected:

1. **Immediate Actions**:
   - Revoke all active sessions
   - Clear localStorage/sessionStorage
   - Unregister service workers
   - Reset user permissions

2. **Investigation**:
   - Identify entry point (SVG, JSON, custom property, etc.)
   - Determine scope of compromise
   - Check for data exfiltration

3. **Remediation**:
   - Patch vulnerability
   - Update CSP/Permission policies
   - Notify affected users
   - Implement additional monitoring

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [Permissions Policy Specification](https://www.w3.org/TR/permissions-policy/)
- [Fabric.js Security Utilities](/api/fabric/namespaces/util/namespaces/string/functions/escapeXml)

## Appendix: Attack Surface Matrix

| Attack Vector | XSS Method | Local Capability | Impact Severity | Mitigation Priority |
|---------------|------------|------------------|-----------------|---------------------|
| SVG Deserialization | Script injection in SVG | File System Access | Critical | High |
| JSON Loading | Malicious object properties | Clipboard API | High | High |
| Image Sources | SVG with embedded scripts | Camera/Microphone | Critical | High |
| Text Objects | Font injection | Geolocation | Medium | Medium |
| Custom Properties | Property deserialization | IndexedDB | High | High |
| Event Handlers | Handler injection | Service Workers | Critical | High |
| URL Parameters | Query string injection | WebRTC | Medium | Medium |
| Export Functions | SVG export XSS | Notifications | Low | Low |

## Change Log

- **2025-12-28**: Initial threat model document created
- Document version: 1.0

---

**Note**: This is a living document. As new attack vectors are discovered or browser capabilities evolve, this threat model should be updated accordingly.
