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
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Set;

final class ServedPocServer
{
    private ServerSocket serverSocket;
    private ExecutorService serverExecutor;
    private int port;
    private final Set<Socket> clients = ConcurrentHashMap.newKeySet();
    private ExecutorService clientExecutor;
    private boolean stopped;
    private volatile byte[] body = new byte[0];

    synchronized URI startOrUpdate(String html, int requestedPort) throws IOException
    {
        if (stopped) throw new IOException("The PoC server has been shut down.");
        if (serverSocket == null || port != requestedPort)
        {
            ServerSocket socket = new ServerSocket();
            try
            {
                socket.setReuseAddress(true);
                socket.bind(new InetSocketAddress("127.0.0.1", requestedPort));
            }
            catch (IOException | RuntimeException exception)
            {
                try { socket.close(); } catch (IOException closeError) { exception.addSuppressed(closeError); }
                throw exception;
            }
            closeResources();
            serverSocket = socket;
            body = html.getBytes(StandardCharsets.UTF_8);
            clientExecutor = new ThreadPoolExecutor(0, 4, 30, TimeUnit.SECONDS,
                new SynchronousQueue<>(), runnable -> {
                    Thread thread = new Thread(runnable, "click-jackalope-client");
                    thread.setDaemon(true);
                    return thread;
                });
            ExecutorService workers = clientExecutor;
            serverExecutor = Executors.newSingleThreadExecutor(runnable ->
            {
                Thread thread = new Thread(runnable, "click-jackalope-poc-server");
                thread.setDaemon(true);
                return thread;
            });
            serverExecutor.submit(() -> serveLoop(socket, workers));
            port = socket.getLocalPort();
        }

        body = html.getBytes(StandardCharsets.UTF_8);
        return URI.create("http://127.0.0.1:" + port + "/");
    }

    synchronized void stop()
    {
        stopped = true;
        closeResources();
    }

    private void closeResources()
    {
        for (Socket client : clients)
        {
            try { client.close(); } catch (IOException ignored) { }
        }
        clients.clear();
        if (clientExecutor != null)
        {
            clientExecutor.shutdownNow();
            clientExecutor = null;
        }
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

    private void serveLoop(ServerSocket socket, ExecutorService workers)
    {
        while (!socket.isClosed())
        {
            try
            {
                Socket client = socket.accept();
                clients.add(client);
                try { workers.execute(() -> handleClient(client)); }
                catch (RejectedExecutionException full) {
                    clients.remove(client);
                    client.close();
                }
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
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);

            // Drain HTTP request headers up to the blank line (\r\n\r\n).
            InputStream in = client.getInputStream();
            int p3 = 0, p2 = 0, p1 = 0, b;
            int bytes = 0;
            while (true)
            {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0 || ++bytes > 16384) return;
                client.setSoTimeout((int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
                b = in.read();
                if (b == -1) return;
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
        finally { clients.remove(client); }
    }
}
