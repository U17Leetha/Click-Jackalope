package com.clickjackalope.burp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

final class ServedPocServer
{
    private HttpServer server;
    private int port;
    private volatile byte[] body = "".getBytes(StandardCharsets.UTF_8);

    synchronized URI startOrUpdate(String html, int requestedPort) throws IOException
    {
        body = html.getBytes(StandardCharsets.UTF_8);

        if (server == null || port != requestedPort)
        {
            stop();
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", requestedPort), 0);
            server.createContext("/", new PocHandler());
            server.setExecutor(Executors.newSingleThreadExecutor(runnable ->
            {
                Thread thread = new Thread(runnable, "click-jackalope-poc-server");
                thread.setDaemon(true);
                return thread;
            }));
            server.start();
            port = requestedPort;
        }

        return URI.create("http://127.0.0.1:" + port + "/");
    }

    synchronized void stop()
    {
        if (server != null)
        {
            server.stop(0);
            server = null;
            port = 0;
        }
    }

    private final class PocHandler implements HttpHandler
    {
        @Override
        public void handle(HttpExchange exchange) throws IOException
        {
            byte[] response = body;
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream outputStream = exchange.getResponseBody())
            {
                outputStream.write(response);
            }
        }
    }
}
