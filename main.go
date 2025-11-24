package main

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"os"

	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"mcp-test/netmon"
)

//go:generate go tool bpf2go -tags linux -go-package netmon -output-dir netmon/ netmon netmon/netmon.c -- -I./netmon/include
func main() {
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
			mcp.Description(
				`The incoming operation measures the number of packets 
				received per second (in the timespan of 5 seconds). 
				The outgoing operation checks for any new TCP connections.`
			),
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
		result, err = netmon.IncomingPacketsPerSecond()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("%.2f", result)), nil
	case "outgoing":
		event, err := netmon.MonitorTcpConnections()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		result := fmt.Sprintf("%-16s %-15s %-6d -> %-15s %-6d",
			event.Comm,
			intToIP(event.Saddr),
			event.Sport,
			intToIP(event.Daddr),
			event.Dport,
		)

		return mcp.NewToolResultText(result), nil
	default:
		return mcp.NewToolResultError(fmt.Sprintf("unknown operation: %s", operation)), nil
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
