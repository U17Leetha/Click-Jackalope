package com.clickjackalope.burp;

import org.junit.jupiter.api.Test;
import java.net.*;
import java.net.http.*;
import java.io.IOException;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.*;

class ServedPocServerTest
{
    @Test
    void busyReplacementPortPreservesOriginalPocAndAllowsRetry() throws Exception
    {
        ServedPocServer server = new ServedPocServer();
        try (ServerSocket occupied = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")))
        {
            URI original = server.startOrUpdate("original", 0);
            IOException error = assertThrows(IOException.class,
                () -> server.startOrUpdate("replacement", occupied.getLocalPort()));
            assertNotNull(error.getMessage());
            assertEquals("original", fetch(original));
            assertEquals(original, server.startOrUpdate("updated", original.getPort()));
            assertEquals("updated", fetch(original));
            URI replacement = server.startOrUpdate("replacement", 0);
            assertNotEquals(original, replacement);
            assertEquals("replacement", fetch(replacement));
        }
        finally { server.stop(); }
    }

    @Test
    void incompleteClientDoesNotBlockOtherRequestsAndClosesOnStop() throws Exception
    {
        ServedPocServer server = new ServedPocServer();
        URI uri = server.startOrUpdate("available", 0);
        try (Socket incomplete = new Socket("127.0.0.1", uri.getPort()))
        {
            incomplete.setSoTimeout(1500);
            incomplete.getOutputStream().write('G');
            assertEquals("available", fetch(uri));
            server.stop();
            assertEquals(-1, incomplete.getInputStream().read());
            assertThrows(IOException.class, () -> server.startOrUpdate("late", 0));
        }
        finally { server.stop(); }
    }

    private static String fetch(URI uri) throws Exception
    {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(3)).build(), HttpResponse.BodyHandlers.ofString()).body();
    }
}
