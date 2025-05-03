import os
import traceback
import glob
from typing import Dict, Optional, List

from .cdb_session import CDBSession, CDBError

from mcp.shared.exceptions import McpError
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    ErrorData,
    TextContent,
    Tool,
    INVALID_PARAMS,
    INTERNAL_ERROR,
)
from pydantic import BaseModel, Field

# Dictionary to store CDB sessions keyed by dump file path
active_sessions: Dict[str, CDBSession] = {}

class OpenWindbgDump(BaseModel):
    """Parameters for analyzing a crash dump."""
    dump_path: str = Field(description="Path to the Windows crash dump file")
    include_stack_trace: bool = Field(
        default=True, 
        description="Whether to include stack traces in the analysis"
    )
    include_modules: bool = Field(
        default=True, 
        description="Whether to include loaded module information"
    )
    include_threads: bool = Field(
        default=True, 
        description="Whether to include thread information"
    )


class RunWindbgCmdParams(BaseModel):
    """Parameters for executing a WinDBG command."""
    dump_path: str = Field(description="Path to the Windows crash dump file")
    command: str = Field(description="WinDBG command to execute")


class CloseWindbgDumpParams(BaseModel):
    """Parameters for unloading a crash dump."""
    dump_path: str = Field(description="Path to the Windows crash dump file to unload")


class ListWindbgDumpsParams(BaseModel):
    """Parameters for listing crash dumps in a directory."""
    directory_path: str = Field(description="Directory path to search for .dmp files")
    recursive: bool = Field(
        default=False,
        description="Whether to search recursively in subdirectories"
    )


def get_or_create_session(
    dump_path: str,
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False
) -> CDBSession:
    """Get an existing CDB session or create a new one."""
    abs_dump_path = os.path.abspath(dump_path)
    
    if abs_dump_path not in active_sessions or active_sessions[abs_dump_path] is None:
        try:
            session = CDBSession(
                dump_path=abs_dump_path,
                cdb_path=cdb_path,
                symbols_path=symbols_path,
                timeout=timeout,
                verbose=verbose
            )
            active_sessions[abs_dump_path] = session
            return session
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Failed to create CDB session: {str(e)}"
            ))
    
    return active_sessions[abs_dump_path]


def unload_session(dump_path: str) -> bool:
    """Unload and clean up a CDB session."""
    abs_dump_path = os.path.abspath(dump_path)
    
    if abs_dump_path in active_sessions and active_sessions[abs_dump_path] is not None:
        try:
            active_sessions[abs_dump_path].shutdown()
            del active_sessions[abs_dump_path]
            return True
        except Exception:
            return False
    
    return False


def execute_common_analysis_commands(session: CDBSession) -> dict:
    """
    Execute common analysis commands and return the results.
    
    Returns a dictionary with the results of various analysis commands.
    """
    results = {}
    
    try:
        results["info"] = session.send_command(".lastevent")
        results["exception"] = session.send_command("!analyze -v")
        results["modules"] = session.send_command("lm")
        results["threads"] = session.send_command("~")
    except CDBError as e:
        results["error"] = str(e)
    
    return results


async def serve(
    cdb_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
) -> None:
    """Run the WinDBG MCP server.

    Args:
        cdb_path: Optional custom path to cdb.exe
        symbols_path: Optional custom symbols path
        timeout: Command timeout in seconds
        verbose: Whether to enable verbose output
    """
    server = Server("mcp-windbg")
    
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="open_windbg_dump",
                description="""
                Analyze a Windows crash dump file using WinDBG/CDB.
                This tool executes common WinDBG commands to analyze the crash dump and returns the results.
                """,
                inputSchema=OpenWindbgDump.model_json_schema(),
            ),
            Tool(
                name="run_windbg_cmd",
                description="""
                Execute a specific WinDBG command on a loaded crash dump.
                This tool allows you to run any WinDBG command on the crash dump and get the output.
                """,
                inputSchema=RunWindbgCmdParams.model_json_schema(),
            ),
            Tool(
                name="close_windbg_dump",
                description="""
                Unload a crash dump and release resources.
                Use this tool when you're done analyzing a crash dump to free up resources.
                """,
                inputSchema=CloseWindbgDumpParams.model_json_schema(),
            ),
            Tool(
                name="list_windbg_dumps",
                description="""
                List Windows crash dump (.dmp) files in the specified directory.
                This tool helps you discover available crash dumps that can be analyzed.
                """,
                inputSchema=ListWindbgDumpsParams.model_json_schema(),
            )
        ]

    @server.call_tool()
    async def call_tool(name, arguments: dict) -> list[TextContent]:
        try:
            if name == "open_windbg_dump":
                args = OpenWindbgDump(**arguments)
                session = get_or_create_session(
                    args.dump_path, cdb_path, symbols_path, timeout, verbose
                )
                
                results = []
                
                crash_info = session.send_command(".lastevent")
                results.append("### Crash Information\n```\n" + "\n".join(crash_info) + "\n```\n\n")
                
                # Run !analyze -v
                analysis = session.send_command("!analyze -v")
                results.append("### Crash Analysis\n```\n" + "\n".join(analysis) + "\n```\n\n")
                
                # Optional
                if args.include_stack_trace:
                    stack = session.send_command("kb")
                    results.append("### Stack Trace\n```\n" + "\n".join(stack) + "\n```\n\n")
                
                if args.include_modules:
                    modules = session.send_command("lm")
                    results.append("### Loaded Modules\n```\n" + "\n".join(modules) + "\n```\n\n")
                
                if args.include_threads:
                    threads = session.send_command("~")
                    results.append("### Threads\n```\n" + "\n".join(threads) + "\n```\n\n")
                
                return [TextContent(
                    type="text",
                    text="".join(results)
                )]
                
            elif name == "run_windbg_cmd":
                args = RunWindbgCmdParams(**arguments)
                session = get_or_create_session(
                    args.dump_path, cdb_path, symbols_path, timeout, verbose
                )
                output = session.send_command(args.command)
                
                return [TextContent(
                    type="text",
                    text=f"Command: {args.command}\n\nOutput:\n```\n" + "\n".join(output) + "\n```"
                )]
                
            elif name == "close_windbg_dump":
                args = CloseWindbgDumpParams(**arguments)
                success = unload_session(args.dump_path)
                if success:
                    return [TextContent(
                        type="text",
                        text=f"Successfully unloaded crash dump: {args.dump_path}"
                    )]
                else:
                    return [TextContent(
                        type="text",
                        text=f"No active session found for crash dump: {args.dump_path}"
                    )]

            elif name == "list_windbg_dumps":
                args = ListWindbgDumpsParams(**arguments)
                
                if not os.path.exists(args.directory_path) or not os.path.isdir(args.directory_path):
                    raise McpError(ErrorData(
                        code=INVALID_PARAMS,
                        message=f"Directory not found: {args.directory_path}"
                    ))
                
                # Determine search pattern based on recursion flag
                search_pattern = os.path.join(args.directory_path, "**", "*.dmp") if args.recursive else os.path.join(args.directory_path, "*.dmp")
                
                # Find all dump files
                dump_files = glob.glob(search_pattern, recursive=args.recursive)
                
                # Sort alphabetically for consistent results
                dump_files.sort()
                
                if not dump_files:
                    return [TextContent(
                        type="text",
                        text=f"No crash dump files (*.dmp) found in {args.directory_path}"
                    )]
                
                # Format the results
                result_text = f"Found {len(dump_files)} crash dump file(s) in {args.directory_path}:\n\n"
                for i, dump_file in enumerate(dump_files):
                    # Get file size in MB
                    try:
                        size_mb = round(os.path.getsize(dump_file) / (1024 * 1024), 2)
                        modified_time = os.path.getmtime(dump_file)
                        modified_str = f"Modified: {os.path.getmtime(dump_file)}"
                    except (OSError, IOError):
                        size_mb = "unknown"
                        modified_str = "Modified: unknown"
                    
                    result_text += f"{i+1}. {dump_file} ({size_mb} MB)\n"
                
                return [TextContent(
                    type="text",
                    text=result_text
                )]
            
            raise McpError(ErrorData(
                code=INVALID_PARAMS,
                message=f"Unknown tool: {name}"
            ))
            
        except McpError:
            raise
        except Exception as e:
            traceback_str = traceback.format_exc()
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing tool {name}: {str(e)}\n{traceback_str}"
            ))
            
    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)

# Clean up function to ensure all sessions are closed when the server exits
def cleanup_sessions():
    """Close all active CDB sessions."""
    for dump_path, session in active_sessions.items():
        try:
            if session is not None:
                session.shutdown()
        except Exception:
            pass
    active_sessions.clear()

# Register cleanup on module exit
import atexit
atexit.register(cleanup_sessions)