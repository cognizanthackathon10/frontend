import React, { useState, useEffect, useMemo } from "react";
import {
  Container,
  Typography,
  Box,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Collapse,
  IconButton,
  TextField,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  CircularProgress,
  Pagination,
  Button,
  Stack,
  Alert,
  Card,
  CardContent,
  LinearProgress
} from "@mui/material";
import {
  KeyboardArrowDown,
  KeyboardArrowUp,
  Search as SearchIcon,
  Download as DownloadIcon,
  CloudUpload as CloudUploadIcon,
  FileUpload as FileUploadIcon,
  Refresh as RefreshIcon
} from "@mui/icons-material";
import axios from "axios";
import { BarChart, Bar, XAxis, YAxis, Tooltip as ReTooltip, ResponsiveContainer } from "recharts";

const SEVERITY_COLORS = {
  CRITICAL: { chip: "error", row: "#e6ccff" },
  HIGH: { chip: "warning", row: "#fdecea" },
  MEDIUM: { chip: "info", row: "#fff8e1" },
  LOW: { chip: "success", row: "#e8f4fd" },
  INFO: { chip: "default", row: "#f7f7f7" },
};

function SeverityChip({ severity }) {
  const sev = severity.toUpperCase();
  const color = SEVERITY_COLORS[sev]?.chip || "default";
  return <Chip label={sev} color={color} size="small" />;
}

function IssueRow({ issue }) {
  const [open, setOpen] = useState(false);
  const sev = issue.severity.toUpperCase();
  const rowColor = SEVERITY_COLORS[sev]?.row || "inherit";

  return (
    <>
      <TableRow hover sx={{ backgroundColor: rowColor }}>
        <TableCell>
          <IconButton size="small" onClick={() => setOpen(!open)}>
            {open ? <KeyboardArrowUp /> : <KeyboardArrowDown />}
          </IconButton>
        </TableCell>
        <TableCell>
          <SeverityChip severity={issue.severity} />
        </TableCell>
        <TableCell>{issue.file}</TableCell>
        <TableCell>{issue.line}</TableCell>
        <TableCell>{issue.category}</TableCell>
        <TableCell>{issue.id}</TableCell>
        <TableCell>{issue.message}</TableCell>
        <TableCell>
          <code>{issue.snippet}</code>
        </TableCell>
        <TableCell>{issue.detected_by}</TableCell>
      </TableRow>
      <TableRow sx={{ backgroundColor: rowColor }}>
        <TableCell colSpan={9} style={{ paddingBottom: 0, paddingTop: 0 }}>
          <Collapse in={open} timeout="auto" unmountOnExit>
            <Box margin={1}>
              <Typography variant="subtitle2" gutterBottom>
                Suggestion:
              </Typography>
              <Typography variant="body2" paragraph>
                {issue.suggestion || "N/A"}
              </Typography>
              <Typography variant="subtitle2" gutterBottom>
                OWASP:
              </Typography>
              <Typography variant="body2" paragraph>
                {issue.owasp || "N/A"}
              </Typography>
              <Typography variant="subtitle2" gutterBottom>
                CWE:
              </Typography>
              <Typography variant="body2">{issue.cwe || "N/A"}</Typography>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

function Filters({ filters, setFilters, owaspOptions, cweOptions }) {
  return (
    <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2, alignItems: "center" }}>
      <FormControl sx={{ minWidth: 120 }}>
        <InputLabel>Severity</InputLabel>
        <Select
          value={filters.severity}
          label="Severity"
          onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
        >
          <MenuItem value="ALL">All</MenuItem>
          {Object.keys(SEVERITY_COLORS).map((sev) => (
            <MenuItem key={sev} value={sev}>
              {sev}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      <FormControl sx={{ minWidth: 140 }}>
        <InputLabel>OWASP</InputLabel>
        <Select
          value={filters.owasp}
          label="OWASP"
          onChange={(e) => setFilters({ ...filters, owasp: e.target.value })}
        >
          <MenuItem value="ALL">All</MenuItem>
          {owaspOptions.map((tag) => (
            <MenuItem key={tag} value={tag}>
              {tag}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      <FormControl sx={{ minWidth: 140 }}>
        <InputLabel>CWE</InputLabel>
        <Select
          value={filters.cwe}
          label="CWE"
          onChange={(e) => setFilters({ ...filters, cwe: e.target.value })}
        >
          <MenuItem value="ALL">All</MenuItem>
          {cweOptions.map((tag) => (
            <MenuItem key={tag} value={tag}>
              {tag}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      <TextField
        label="Search"
        variant="outlined"
        size="small"
        sx={{ flexGrow: 1, minWidth: 200 }}
        value={filters.search}
        onChange={(e) => setFilters({ ...filters, search: e.target.value })}
        InputProps={{
          endAdornment: <SearchIcon />,
        }}
      />
    </Box>
  );
}

function SeverityChart({ issues }) {
  const data = useMemo(() => {
    const counts = {};
    issues.forEach((i) => {
      const sev = i.severity.toUpperCase();
      counts[sev] = (counts[sev] || 0) + 1;
    });
    return Object.entries(counts).map(([severity, count]) => ({
      severity,
      count,
    }));
  }, [issues]);

  return (
    <Box sx={{ width: "100%", height: 200, mb: 3 }}>
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 20, bottom: 20 }}>
          <XAxis dataKey="severity" />
          <YAxis allowDecimals={false} />
          <ReTooltip />
          <Bar dataKey="count" fill="#1976d2" label={{ position: "top", fill: "#1976d2" }} />
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
}

const PAGE_SIZE = 15;

function App() {
  const [issues, setIssues] = useState([]);
  const [loading, setLoading] = useState(false); // Changed to false since we don't load old reports
  const [hasUploadedFile, setHasUploadedFile] = useState(false);
  const [viewMode, setViewMode] = useState('results'); // 'upload' or 'results'
  const [filters, setFilters] = useState({
    severity: "ALL",
    owasp: "ALL",
    cwe: "ALL",
    search: "",
  });
  const [page, setPage] = useState(1);

  // File upload states
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadLoading, setUploadLoading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [uploadSuccess, setUploadSuccess] = useState(null);
  const [uploadedFileName, setUploadedFileName] = useState(null);

  // Try to load existing report.json if backend is running, otherwise show upload interface
  useEffect(() => {
    // Add multiple cache-busting parameters to ensure fresh loading
    const timestamp = Date.now();
    const randomId = Math.random().toString(36).substring(7);
    const cacheBust = `?t=${timestamp}&r=${randomId}&v=${timestamp}`;

    axios
      .get(`/reports/report.json${cacheBust}`, {
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      })
      .then((res) => {
        setIssues(res.data);
        setLoading(false);
        setHasUploadedFile(true); // Mark as having data from backend
      })
      .catch((err) => {
        console.error("Backend not running or no report.json found, showing upload interface", err);
        setLoading(false);
        setHasUploadedFile(false); // No backend data available
      });
  }, []);

  // Handle file upload
  const handleFileUpload = async () => {
    if (!uploadFile) {
      setUploadError("Please select a file first");
      return;
    }

    setUploadLoading(true);
    setUploadError(null);
    setUploadSuccess(null);

    const formData = new FormData();
    formData.append('file', uploadFile);

  try {
  const API_BASE = process.env.REACT_APP_API_BASE_URL || '';

  const response = await axios.post(`${API_BASE}/upload`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });

  if (response.data.success) {
    setIssues(response.data.issues);
    setUploadedFileName(response.data.file_name);
    setUploadSuccess(
      `Successfully analyzed ${response.data.file_name}. Found ${response.data.total_issues} issues.`
    );
    setHasUploadedFile(true);
    setPage(1);
  } else {
    setUploadError(response.data.error || "Upload failed");
  }
} catch (error) {
  console.error("Upload error:", error);
  setUploadError(error.response?.data?.error || "Failed to upload and analyze file");
} finally {
  setUploadLoading(false);
}

  }

  // Handle file selection
  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file) {
      // Validate file type
      const allowedExtensions = ['.js', '.php'];
      const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));

      if (!allowedExtensions.includes(fileExtension)) {
        setUploadError("Only .js and .php files are supported");
        setUploadFile(null);
        return;
      }

      setUploadFile(file);
      setUploadError(null);
      setUploadSuccess(null);
    }
  };

  const owaspOptions = useMemo(() => {
    const set = new Set();
    issues.forEach((i) => {
      if (i.owasp) i.owasp.split(",").forEach((tag) => tag && set.add(tag.trim()));
    });
    return Array.from(set).sort();
  }, [issues]);

  const cweOptions = useMemo(() => {
    const set = new Set();
    issues.forEach((i) => {
      if (i.cwe) i.cwe.split(",").forEach((tag) => tag && set.add(tag.trim()));
    });
    return Array.from(set).sort();
  }, [issues]);

  const filteredIssues = useMemo(() => {
    return issues.filter((issue) => {
      if (filters.severity !== "ALL" && issue.severity.toUpperCase() !== filters.severity) return false;
      if (filters.owasp !== "ALL" && !issue.owasp.includes(filters.owasp)) return false;
      if (filters.cwe !== "ALL" && !issue.cwe.includes(filters.cwe)) return false;
      if (filters.search && !JSON.stringify(issue).toLowerCase().includes(filters.search.toLowerCase())) return false;
      return true;
    });
  }, [issues, filters]);

  const pageCount = Math.ceil(filteredIssues.length / PAGE_SIZE);
  const pagedIssues = filteredIssues.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleDownload = (format) => {
    // Check if we have results from either upload or backend
    if (issues.length > 0) {
      const content = format === "html" ? generateHtmlReport(issues) : JSON.stringify(issues, null, 2);
      const blob = new Blob([content], {
        type: format === "html" ? "text/html" : "application/json",
      });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `report.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      return;
    }

    // If no results available, show message to upload first
    alert("Please upload a suitable file first before downloading reports.");
  };

  // Helper to generate HTML report string from issues
  const generateHtmlReport = (issues) => {
    // Extract unique values for filters
    const severities = [...new Set(issues.map(i => i.severity.toUpperCase()))].sort();
    const owaspTags = [...new Set(issues.flatMap(i => (i.owasp || '').split(',').map(tag => tag.trim())).filter(tag => tag))].sort();
    const cweTags = [...new Set(issues.flatMap(i => (i.cwe || '').split(',').map(tag => tag.trim())).filter(tag => tag))].sort();

    let html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Secure Code Analyzer Report</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
          .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
          .header { text-align: center; margin-bottom: 30px; }
          .filters { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
          .filter-group { display: flex; flex-direction: column; min-width: 150px; }
          .filter-group label { font-weight: bold; margin-bottom: 5px; }
          .filter-group select, .filter-group input { padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
          .summary { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
          table { border-collapse: collapse; width: 100%; margin-top: 20px; }
          th, td { border: 1px solid #ccc; padding: 12px; text-align: left; }
          th { background: #007bff; color: white; font-weight: bold; }
          .CRITICAL { background-color: #f5c6cb; }
          .HIGH { background-color: #f8d7da; }
          .MEDIUM { background-color: #fff3cd; }
          .LOW { background-color: #d1ecf1; }
          .INFO { background-color: #f7f7f7; }
          .hidden { display: none; }
          .chart-container { margin: 20px 0; }
          .severity-chart { display: flex; flex-direction: column; gap: 8px; margin: 20px 0; max-width: 400px; }
          .severity-bar { display: flex; align-items: center; padding: 8px 12px; border-radius: 6px; color: white; font-weight: bold; font-size: 14px; min-height: 40px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
          .severity-bar span:first-child { flex: 0 0 80px; }
          .severity-bar span:last-child { margin-left: auto; font-size: 12px; opacity: 0.9; }
          .critical-bar { background: linear-gradient(90deg, #dc3545, #c82333); }
          .high-bar { background: linear-gradient(90deg, #fd7e14, #e8680f); }
          .medium-bar { background: linear-gradient(90deg, #ffc107, #e0a800); }
          .low-bar { background: linear-gradient(90deg, #28a745, #1e7e34); }
          .info-bar { background: linear-gradient(90deg, #6c757d, #5a6268); }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Secure Code Analyzer Report</h1>
            <p>Generated at: ${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC</p>
          </div>

          <div class="summary">
            <strong>Total issues found: <span id="total-issues">${issues.length}</span></strong>
          </div>

          <div class="filters">
            <div class="filter-group">
              <label for="severity-filter">Severity:</label>
              <select id="severity-filter">
                <option value="ALL">All</option>
                ${severities.map(s => `<option value="${s}">${s}</option>`).join('')}
              </select>
            </div>

            <div class="filter-group">
              <label for="owasp-filter">OWASP:</label>
              <select id="owasp-filter">
                <option value="ALL">All</option>
                ${owaspTags.map(tag => `<option value="${tag}">${tag}</option>`).join('')}
              </select>
            </div>

            <div class="filter-group">
              <label for="cwe-filter">CWE:</label>
              <select id="cwe-filter">
                <option value="ALL">All</option>
                ${cweTags.map(tag => `<option value="${tag}">${tag}</option>`).join('')}
              </select>
            </div>

            <div class="filter-group">
              <label for="search-filter">Search:</label>
              <input type="text" id="search-filter" placeholder="Search issues...">
            </div>
          </div>

          <div class="severity-chart" id="severity-chart">
            ${generateSeverityChart(issues)}
          </div>

          <table id="issues-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>File</th>
                <th>Line</th>
                <th>Category</th>
                <th>Rule</th>
                <th>Message</th>
                <th>Snippet</th>
                <th>OWASP</th>
                <th>CWE</th>
              </tr>
            </thead>
            <tbody>
    `;

    issues.forEach((issue, index) => {
      const severityClass = issue.severity.toUpperCase();
      html += `
        <tr class="${severityClass}" data-severity="${issue.severity.toUpperCase()}" data-owasp="${issue.owasp || ''}" data-cwe="${issue.cwe || ''}" data-message="${issue.message.toLowerCase()}">
          <td><span style="padding: 4px 8px; border-radius: 4px; background: ${getSeverityColor(issue.severity)}; color: white; font-weight: bold;">${issue.severity}</span></td>
          <td>${issue.file}</td>
          <td>${issue.line}</td>
          <td>${issue.category || 'N/A'}</td>
          <td>${issue.id || 'N/A'}</td>
          <td>${issue.message}</td>
          <td><code>${issue.snippet || 'N/A'}</code></td>
          <td>${issue.owasp || 'N/A'}</td>
          <td>${issue.cwe || 'N/A'}</td>
        </tr>
      `;
    });

    html += `
            </tbody>
          </table>
        </div>

        <script>
          function filterIssues() {
            const severityFilter = document.getElementById('severity-filter').value;
            const owaspFilter = document.getElementById('owasp-filter').value;
            const cweFilter = document.getElementById('cwe-filter').value;
            const searchFilter = document.getElementById('search-filter').value.toLowerCase();
            const rows = document.querySelectorAll('#issues-table tbody tr');
            let visibleCount = 0;

            rows.forEach(row => {
              const severity = row.dataset.severity;
              const owasp = row.dataset.owasp;
              const cwe = row.dataset.cwe;
              const message = row.dataset.message;

              const severityMatch = severityFilter === 'ALL' || severity === severityFilter;
              const owaspMatch = owaspFilter === 'ALL' || owasp.includes(owaspFilter);
              const cweMatch = cweFilter === 'ALL' || cwe.includes(cweFilter);
              const searchMatch = !searchFilter || message.includes(searchFilter);

              if (severityMatch && owaspMatch && cweMatch && searchMatch) {
                row.style.display = '';
                visibleCount++;
              } else {
                row.style.display = 'none';
              }
            });

            document.getElementById('total-issues').textContent = visibleCount;
          }

          // Add event listeners
          document.getElementById('severity-filter').addEventListener('change', filterIssues);
          document.getElementById('owasp-filter').addEventListener('change', filterIssues);
          document.getElementById('cwe-filter').addEventListener('change', filterIssues);
          document.getElementById('search-filter').addEventListener('input', filterIssues);
        </script>
      </body>
      </html>
    `;
    return html;
  };

  // Helper function to generate severity chart
  const generateSeverityChart = (issues) => {
    const counts = {};
    issues.forEach(issue => {
      const sev = issue.severity.toUpperCase();
      counts[sev] = (counts[sev] || 0) + 1;
    });

    const total = issues.length;
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

    return severities.map(sev => {
      const count = counts[sev] || 0;
      const percentage = total > 0 ? Math.round((count / total) * 100) : 0;
      const className = sev.toLowerCase() + '-bar';
      return `<div class="severity-bar ${className}"><span>${sev}</span><span>${count} (${percentage}%)</span></div>`;
    }).join('');
  };

  // Helper function to get severity color
  const getSeverityColor = (severity) => {
    const sev = severity.toUpperCase();
    switch(sev) {
      case 'CRITICAL': return '#dc3545';
      case 'HIGH': return '#fd7e14';
      case 'MEDIUM': return '#ffc107';
      case 'LOW': return '#28a745';
      case 'INFO': return '#6c757d';
      default: return '#6c757d';
    }
  };

  // Helper functions for HTML report
  const getSeverityDescription = (severity) => {
    const sev = severity.toUpperCase();
    switch(sev) {
      case 'CRITICAL':
        return 'Critical severity issues can lead to immediate security vulnerabilities such as SQL Injection, Command Injection, or Code Execution.';
      case 'HIGH':
        return 'High severity issues can lead to immediate security vulnerabilities such as SQL Injection, Command Injection, or Code Execution.';
      case 'MEDIUM':
        return 'Medium severity issues may expose sensitive information or weaken security (e.g., weak hashing, DOM-based XSS).';
      case 'LOW':
        return 'Low severity issues include bad practices or information leakage that could help attackers.';
      case 'INFO':
        return 'Informational issues that may not be security vulnerabilities but could be improved.';
      default:
        return 'Security issue detected.';
    }
  };

  const getSeverityAction = (severity) => {
    const sev = severity.toUpperCase();
    switch(sev) {
      case 'CRITICAL':
        return 'Fix immediately. Use input validation, sanitization, parameterized queries, and avoid dangerous functions.';
      case 'HIGH':
        return 'Fix immediately. Use input validation, sanitization, parameterized queries, and avoid dangerous functions.';
      case 'MEDIUM':
        return 'Mitigate soon. Use secure cryptography, escape/encode output, and review business logic.';
      case 'LOW':
        return 'Fix when possible. Remove debugging code, avoid leaking system info, and improve secure coding practices.';
      case 'INFO':
        return 'Review and consider improvements.';
      default:
        return 'Review and fix the security issue.';
    }
  };

  if (loading)
    return (
      <Container sx={{ textAlign: "center", mt: 10 }}>
        <CircularProgress />
        <Typography variant="h6" mt={2}>
          Loading report...
        </Typography>
      </Container>
    );

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
        <Typography variant="h4">
          {uploadedFileName ? `Analysis Results: ${uploadedFileName}` : 'Secure Code Analyzer Report'}
        </Typography>
        <Stack direction="row" spacing={2} alignItems="center">
          <Button
            variant={viewMode === 'upload' ? 'contained' : 'outlined'}
            onClick={() => setViewMode('upload')}
            startIcon={<CloudUploadIcon />}
          >
            Upload File
          </Button>
          <Button
            variant={viewMode === 'results' ? 'contained' : 'outlined'}
            onClick={() => setViewMode('results')}
            startIcon={<DownloadIcon />}
          >
            View Results
          </Button>
          <Button
            variant={viewMode === 'cli' ? 'contained' : 'outlined'}
            onClick={() => setViewMode('cli')}
            startIcon={<FileUploadIcon />}
          >
            CLI Commands
          </Button>
          <Button
            variant="outlined"
            onClick={() => {
              setLoading(true);
              const timestamp = Date.now();
              const randomId = Math.random().toString(36).substring(7);
              const cacheBust = `?t=${timestamp}&r=${randomId}&v=${timestamp}`;

              axios.get(`/reports/report.json${cacheBust}`, {
                headers: {
                  'Cache-Control': 'no-cache, no-store, must-revalidate',
                  'Pragma': 'no-cache',
                  'Expires': '0'
                }
              })
                .then((res) => {
                  setIssues(res.data);
                  setLoading(false);
                  setHasUploadedFile(true);
                  setViewMode('results');
                })
                .catch((err) => {
                  console.error("Failed to refresh report.json", err);
                  setLoading(false);
                });
            }}
            startIcon={<RefreshIcon />}
            title="Refresh Report"
          >
            Refresh
          </Button>
        </Stack>
      </Stack>

      {viewMode === 'upload' ? (
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Typography variant="h5" gutterBottom>
              <CloudUploadIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Upload File for Analysis
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Upload a JavaScript (.js) or PHP (.php) file to scan for security vulnerabilities
            </Typography>

            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 2 }}>
              <Button
                variant="outlined"
                component="label"
                startIcon={<FileUploadIcon />}
                sx={{ minWidth: 200 }}
              >
                Choose File
                <input
                  type="file"
                  hidden
                  accept=".js,.php"
                  onChange={handleFileChange}
                />
              </Button>

              {uploadFile && (
                <Typography variant="body2" sx={{ flexGrow: 1 }}>
                  Selected: <strong>{uploadFile.name}</strong> ({(uploadFile.size / 1024).toFixed(1)} KB)
                </Typography>
              )}

              <Button
                variant="contained"
                onClick={handleFileUpload}
                disabled={!uploadFile || uploadLoading}
                startIcon={uploadLoading ? <CircularProgress size={20} /> : <CloudUploadIcon />}
              >
                {uploadLoading ? 'Analyzing...' : 'Analyze File'}
              </Button>
            </Box>

            {uploadLoading && (
              <Box sx={{ mb: 2 }}>
                <LinearProgress />
                <Typography variant="body2" sx={{ mt: 1 }}>
                  Analyzing file for security vulnerabilities...
                </Typography>
              </Box>
            )}

            {uploadError && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {uploadError}
              </Alert>
            )}

            {uploadSuccess && (
              <Alert severity="success" sx={{ mb: 2 }}>
                {uploadSuccess}
              </Alert>
            )}
          </CardContent>
        </Card>
      ) : viewMode === 'results' ? (
        <>
          <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
            <Button variant="contained" startIcon={<DownloadIcon />} onClick={() => handleDownload("json")}>
              Download JSON
            </Button>
            <Button variant="contained" startIcon={<DownloadIcon />} onClick={() => handleDownload("html")}>
              Download HTML
            </Button>
          </Stack>

          <SeverityChart issues={filteredIssues} />

          <Filters filters={filters} setFilters={setFilters} owaspOptions={owaspOptions} cweOptions={cweOptions} />

          <Paper>
            <TableContainer>
              <Table stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell />
                    <TableCell>Severity</TableCell>
                    <TableCell>File</TableCell>
                    <TableCell>Line</TableCell>
                    <TableCell>Category</TableCell>
                    <TableCell>Rule</TableCell>
                    <TableCell>Message</TableCell>
                    <TableCell>Snippet</TableCell>
                    <TableCell>Detected By</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pagedIssues.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={9} align="center">
                        No issues found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    pagedIssues.map((issue, idx) => <IssueRow key={`${issue.file}-${issue.line}-${idx}`} issue={issue} />)
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {pageCount > 1 && (
            <Box sx={{ display: "flex", justifyContent: "center", mt: 3 }}>
              <Pagination count={pageCount} page={page} onChange={(_, value) => setPage(value)} color="primary" />
            </Box>
          )}

          <Box sx={{ mt: 4, textAlign: "center", color: "text.secondary" }}>
            <Typography variant="caption">
              Showing {pagedIssues.length} of {filteredIssues.length} filtered issues (Total: {issues.length})
            </Typography>
          </Box>
        </>
      ) : viewMode === 'cli' ? (
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Typography variant="h5" gutterBottom>
              <FileUploadIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              CLI Commands & Usage
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Use these commands to run the Secure Code Analyzer from the command line
            </Typography>

            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ color: 'primary.main' }}>
                Basic CLI Scanning
              </Typography>
              <Paper sx={{ p: 2, bgcolor: 'grey.50', fontFamily: 'monospace' }}>
                <Typography variant="body2" component="div">
                  <strong>Scan files or directories:</strong><br />
                  python -m secure_code_analyzer.cli samples/js/ samples/php/<br /><br />

                  <strong>Scan with summary:</strong><br />
                  python -m secure_code_analyzer.cli samples --summary<br /><br />

                  <strong>Save reports:</strong><br />
                  python -m secure_code_analyzer.cli samples --out report.json --html report.html
                </Typography>
              </Paper>
            </Box>

            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ color: 'primary.main' }}>
                Web Server Mode
              </Typography>
              <Paper sx={{ p: 2, bgcolor: 'grey.50', fontFamily: 'monospace' }}>
                <Typography variant="body2" component="div">
                  <strong>Start web server:</strong><br />
                  python -m secure_code_analyzer.cli serve<br /><br />

                  <strong>Start on specific port:</strong><br />
                  python -m secure_code_analyzer.cli serve --port 8080<br /><br />

                  <strong>Start on specific host:</strong><br />
                  python -m secure_code_analyzer.cli serve --host 0.0.0.0 --port 5000
                </Typography>
              </Paper>
            </Box>

            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ color: 'primary.main' }}>
                Supported File Types
              </Typography>
              <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                <Typography variant="body2" component="div">
                  <strong>JavaScript files:</strong> .js<br />
                  <strong>PHP files:</strong> .php<br /><br />
                  The analyzer supports various security vulnerability patterns including:<br />
                  • SQL Injection<br />
                  • Cross-Site Scripting (XSS)<br />
                  • Command Injection<br />
                  • Code Injection<br />
                  • Weak Cryptography<br />
                  • And many more...
                </Typography>
              </Paper>
            </Box>

            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ color: 'primary.main' }}>
                Current Backend Status
              </Typography>
              <Paper sx={{ p: 2, bgcolor: hasUploadedFile ? 'success.light' : 'warning.light' }}>
                <Typography variant="body2">
                  <strong>Status:</strong> {hasUploadedFile ? 'Active - Results Available' : 'Ready - No Analysis Results'}<br />
                  <strong>Mode:</strong> {hasUploadedFile ? 'Backend Connected' : 'CLI/Web Upload Mode'}<br />
                  <strong>Issues Found:</strong> {issues.length > 0 ? issues.length : 'None'}
                </Typography>
              </Paper>
            </Box>

            <Alert severity="info">
              <Typography variant="body2">
                <strong>Tip:</strong> When you run the CLI with 'serve' command first, the web interface will automatically load existing results. Otherwise, use the Upload File tab to analyze new files.
              </Typography>
            </Alert>
          </CardContent>
        </Card>
      ) : null}
    </Container>
  );
}

export default App;
