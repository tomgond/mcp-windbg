# MCP Server for WinDBG Crash Analysis

A Model Context Protocol server providing tools to analyze Windows crash dumps using WinDBG/CDB.

## Overview

This MCP server integrates with [CDB](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/opening-a-crash-dump-file-using-cdb) to enable AI models to analyze Windows crash dumps.

## Prerequisites

- Python 3.10 or higher
- Windows operating system with **Debugging Tools for Windows** installed.
  - This is part of the [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/).

## Development Setup

1. Clone the repository:

```bash
git clone https://github.com/svnscha/mcp-windbg.git
cd mcp-windbg
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
.\.venv\Scripts\activate
```

3. Install the package in development mode:

```bash
pip install -e .
```

4. Install test dependencies:

```bash
pip install -e ".[test]"
```

## Usage

### Starting the MCP Server

Start the server using the module command:

```bash
python -m mcp_server_windbg
```

### Command Line Options

```bash
python -m mcp_server_windbg [options]
```

Available options:

- `--cdb-path CDB_PATH`: Custom path to cdb.exe
- `--symbols-path SYMBOLS_PATH`: Custom symbols path
- `--timeout TIMEOUT`: Command timeout in seconds (default: 30)
- `--verbose`: Enable verbose output

### Integrating with VS Code

To integrate this MCP server with Visual Studio Code:

1. Create a `.vscode/mcp.json` file in your project with the following configuration:

```json
{
    "servers": {
        "mcp_server_windbg": {
            "type": "stdio",
            "command": "${workspaceFolder}/.venv/Scripts/python",
            "args": [
                "-m",
                "mcp_server_windbg"
            ],
            "env": {
                "_NT_SYMBOL_PATH": "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols"
            }
        },
    }
}
```

2. Customize the configuration as needed:
   - Adjust the Python interpreter path if needed
   - Set custom paths for CDB by adding `"--cdb-path": "C:\\path\\to\\cdb.exe"` to the `args` array
   - Set the symbol path environment variable as shown above, or add `"--symbols-path"` to the args

### Integration with Copilot

Once the server is configured in VS Code:

1. Enable MCP in Chat feature in Copilot settings
2. The MCP server will appear in Copilot's available tools
3. The WinDBG analysis capabilities will be accessible through Copilot's interface
4. You can now analyze crash dumps directly through Copilot using natural language queries

## Tools

This server provides the following tools:

- `open_windbg_dump`: Analyze a Windows crash dump file using common WinDBG commands
- `run_windbg_cmd`: Execute a specific WinDBG command on the loaded crash dump
- `list_windbg_dumps`: List Windows crash dump (.dmp) files in the specified directory.
- `close_windbg_dump`: Unload a crash dump and release resources

## Running Tests

To run the tests:

```bash
pytest
```

## Troubleshooting

### CDB Not Found

If you get a "CDB executable not found" error, make sure:

1. WinDBG/CDB is installed on your system
2. The CDB executable is in your system PATH, or
3. You specify the path using the `--cdb-path` option

### Symbol Path Issues

For proper crash analysis, set up your symbol path:

1. Use the `--symbols-path` parameter, or
2. Set the `_NT_SYMBOL_PATH` environment variable

### Common Symbol Paths

```
SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols
```

## License

MIT