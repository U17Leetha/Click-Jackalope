package com.clickjackalope.burp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class ServedPocServer
{
    private ServerSocket serverSocket;
    private ExecutorService serverExecutor;
    private int port;
    private volatile byte[] body = new byte[0];

    synchronized URI startOrUpdate(String html, int requestedPort) throws IOException
    {
        body = html.getBytes(StandardCharsets.UTF_8);

        if (serverSocket == null || port != requestedPort)
        {
            stop();
            ServerSocket socket = new ServerSocket();
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress("127.0.0.1", requestedPort));
            serverSocket = socket;
            serverExecutor = Executors.newSingleThreadExecutor(runnable ->
            {
                Thread thread = new Thread(runnable, "click-jackalope-poc-server");
                thread.setDaemon(true);
                return thread;
            });
            serverExecutor.submit(() -> serveLoop(socket));
            port = requestedPort;
        }

        return URI.create("http://127.0.0.1:" + port + "/");
    }

    synchronized void stop()
    {
        if (serverSocket != null)
        {
            try
            {
                serverSocket.close();
            }
            catch (IOException ignored) {}
            serverSocket = null;
            port = 0;
        }

        if (serverExecutor != null)
        {
            serverExecutor.shutdownNow();
            serverExecutor = null;
        }
    }

    private void serveLoop(ServerSocket socket)
    {
        while (!socket.isClosed())
        {
            try
            {
                handleClient(socket.accept());
            }
            catch (SocketException ignored)
            {
                // ServerSocket was closed — exit cleanly.
                break;
            }
            catch (IOException ignored)
            {
                // Individual accept error; keep serving.
            }
        }
    }

    private void handleClient(Socket client)
    {
        try (client)
        {
            client.setSoTimeout(5000);

            // Drain HTTP request headers up to the blank line (\r\n\r\n).
            InputStream in = client.getInputStream();
            int p3 = 0, p2 = 0, p1 = 0, b;
            while ((b = in.read()) != -1)
            {
                if (p3 == '\r' && p2 == '\n' && p1 == '\r' && b == '\n')
                {
                    break;
                }
                p3 = p2;
                p2 = p1;
                p1 = b;
            }

            byte[] response = body;
            String headers = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/html; charset=utf-8\r\n" +
                "Content-Length: " + response.length + "\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n" +
                "\r\n";

            OutputStream out = client.getOutputStream();
            out.write(headers.getBytes(StandardCharsets.US_ASCII));
            out.write(response);
            out.flush();
        }
        catch (IOException ignored) {}
    }
}
