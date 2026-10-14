export interface CodeSample {
  id: string;
  name: string;
  language: string;
  filename: string;
  description: string;
  code: string;
}

export const SAMPLE_CODE_SNIPPETS: CodeSample[] = [
  {
    id: 'sqli-auth',
    name: 'SQL Injection & Auth Bypass',
    language: 'javascript',
    filename: 'auth-controller.js',
    description: 'Vulnerable string concatenation in SQL queries and missing password hashing',
    code: `const express = require('express');
const router = express.Router();
const db = require('./database');

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // CRITICAL VULNERABILITY: Raw SQL String Concatenation
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  console.log("Executing SQL: " + query);

  try {
    const user = await db.query(query);
    if (user.length > 0) {
      // Missing proper session token generation
      res.json({ success: true, user: user[0], role: user[0].role });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (err) {
    // Empty catch block swallows errors silently
  }
});

module.exports = router;`,
  },
  {
    id: 'xss-react',
    name: 'DOM XSS & Insecure Evaluation',
    language: 'typescript',
    filename: 'CommentFeed.tsx',
    description: 'Unescaped dangerouslySetInnerHTML and dynamic eval execution',
    code: `import React, { useState } from 'react';

interface CommentProps {
  rawUserComment: string;
  customFilterScript?: string;
}

export const CommentFeed: React.FC<CommentProps> = ({ rawUserComment, customFilterScript }) => {
  // HIGH RISK: Executing untrusted user script dynamically
  if (customFilterScript) {
    eval(customFilterScript);
  }

  return (
    <div className="comment-box">
      <h3>User Submission:</h3>
      {/* CRITICAL XSS: Direct unescaped HTML injection */}
      <div dangerouslySetInnerHTML={{ __html: rawUserComment }} />
    </div>
  );
};`,
  },
  {
    id: 'aws-crypto',
    name: 'Hardcoded AWS Key & Weak MD5 Hash',
    language: 'python',
    filename: 'cloud_storage.py',
    description: 'Committed cloud credentials and deprecated cryptographic hashing algorithm',
    code: `import hashlib
import boto3

# CRITICAL SECURITY VULNERABILITY: Committed Production Credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def hash_user_password(raw_password: str) -> str:
    # VULNERABILITY: MD5 is cryptographically broken and prone to collision attacks
    hasher = hashlib.md5()
    hasher.update(raw_password.encode('utf-8'))
    return hasher.hexdigest()

def upload_backup(filename: str):
    s3 = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    s3.upload_file(filename, 'company-production-backups', filename)`,
  },
  {
    id: 'cmd-injection',
    name: 'Command Injection & Path Traversal',
    language: 'javascript',
    filename: 'export-utility.js',
    description: 'Unsanitized parameters passed to child_process.exec',
    code: `const { exec } = require('child_process');
const fs = require('fs');

function convertDocument(userFileName, outputFormat) {
  // CRITICAL COMMAND INJECTION: String interpolation into shell execution
  const cmd = \`libreoffice --headless --convert-to \${outputFormat} /tmp/uploads/\${userFileName}\`;
  
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error(\`Execution error: \${error}\`);
      return;
    }
    console.log(\`File converted: \${stdout}\`);
  });
}

module.exports = { convertDocument };`,
  },
];

export const SAMPLE_URLS = [
  {
    url: 'https://news.ycombinator.com',
    label: 'Hacker News (Lightweight HTML)',
  },
  {
    url: 'https://example.com',
    label: 'Example.com (Baseline RFC standard)',
  },
  {
    url: 'https://github.com',
    label: 'GitHub.com (High-Security CSP & HSTS)',
  },
  {
    url: 'https://httpbin.org/html',
    label: 'HttpBin Test HTML',
  },
];
