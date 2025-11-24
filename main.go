package main

import (
	"context"
	"log"
	"os"

	//"encoding/json"
	"fmt"

	"github.com/cilium/ebpf/rlimit"
	//"time"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"mcp-test/ebpf"
)

//go:generate go tool bpf2go -tags linux -go-package ebpf -output-dir ebpf/ netmon ebpf/netmonitor.c
func main() {
	//Raise an error if MEMLOCK rlimit fails to raise
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("warning: could not remove mem lock: %s", err)
	}
	// Create MCP Server instance
	s := server.NewMCPServer("network-mcp_server",
		"0.1.0",
		server.WithToolCapabilities(true),
		server.WithRecovery(),
	)
	transport := os.Getenv("MCP_TRANSPORT")
	port := os.Getenv("MCP_PORT")
	if port == "" {
		port = "8080"
	}

	netTool := mcp.NewTool("network-monitor",
		mcp.WithDescription("Monitor network traffic."),
		mcp.WithString("network_operation",
			mcp.Required(),
			mcp.Enum("incoming", "outgoing"),
			mcp.Description("Network traffic to monitor."),
		),
	)

	s.AddTool(netTool, handleNetworkTraffic)

	// Start MCP Server via HTTP on port 8080 via localhost
	switch transport {
	case "http":
		httpServer := server.NewStreamableHTTPServer(s,
			server.WithEndpointPath("/mcp"))
		log.Println("Listening on port:")
		if err := httpServer.Start(":" + port); err != nil {
			log.Fatal(err)
		}
	case "sse":
		sseServer := server.NewSSEServer(s)
		if err := sseServer.Start(":" + port); err != nil {
			log.Fatal(err)
		}
	default:
		log.Println("Listening on stdio...")
		if err := server.ServeStdio(s); err != nil {
			log.Fatal(err)
		}
	}

}

func handleNetworkTraffic(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Extract parameters using helper methods
	operation, err := req.RequireString("network_operation")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var result float32

	switch operation {
	case "incoming":
		result, err = ebpf.IncomingPacketsPerSecond()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		// Return result
		return mcp.NewToolResultText(fmt.Sprintf("%.2f", result)), nil
	case "outgoing":
		return mcp.NewToolResultError(fmt.Sprintf("unknown operation: %s", operation)), nil
	default:
		return mcp.NewToolResultError(fmt.Sprintf("unknown operation: %s", operation)), nil
	}
}
