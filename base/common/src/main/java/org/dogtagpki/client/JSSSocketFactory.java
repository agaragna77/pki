//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Arrays;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.http.HttpHost;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.protocol.HttpContext;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.mozilla.jss.ssl.SSLAlertDescription;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLAlertLevel;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocketListener;
import org.mozilla.jss.ssl.javax.JSSSocket;

import com.netscape.certsrv.client.PKIConnection;

/**
 * This class provides a ocket factory for PKIConnection based on JSSSocket.
 *
 * JSSSocket support both communication models: sync and async. The model is
 * defined in the initial socket and if not specified it is sync.
 */
public class JSSSocketFactory implements LayeredConnectionSocketFactory {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JSSSocketFactory.class);

    PKIConnection connection;

    public JSSSocketFactory(PKIConnection connection) {
        this.connection = connection;
    }

    @Override
    public Socket createSocket(HttpContext arg0) throws IOException {
        return SocketFactory.getDefault().createSocket();
    }

    @Override
    public Socket createLayeredSocket(Socket socket, String remoteHost, int port, HttpContext context)
            throws IOException, UnknownHostException {

        if (connection.getConfig().getCertNickname() != null) {
            return createNativeClientAuthSocket(socket, remoteHost, port);
        }

        return createJSSSocket(socket, remoteHost, port);
    }

    private Socket createNativeClientAuthSocket(Socket socket, String remoteHost, int port)
            throws IOException {

        try {
            CryptoManager.getInstance();

            SSLCertificateApprovalCallback callback =
                    ClientSSLApprovalCallback.create(connection, remoteHost);

            SSLSocket sslSocket;
            if (socket == null) {
                logger.debug("JSSSocketFactory: Creating native SSL socket");
                sslSocket = new SSLSocket(remoteHost, port, null, 0, callback, null);
            } else {
                logger.debug("JSSSocketFactory: Creating native SSL socket with existing socket");
                sslSocket = new SSLSocket(socket, remoteHost, callback, null);
            }

            sslSocket.setUseClientMode(true);

            String certNickname = connection.getConfig().getCertNickname();
            String resolvedNickname = ClientCertNickname.resolve(connection.getConfig());
            logger.debug("JSSSocketFactory: - client certificate: " + certNickname);
            logger.info("Client certificate: " + resolvedNickname);
            sslSocket.setClientCertNickname(resolvedNickname);

            addSocketListener(sslSocket);
            sslSocket.forceHandshake();
            return sslSocket;

        } catch (SocketException e) {
            throw new IOException("Unable to configure client certificate: " + e.getMessage(), e);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Unable to create SSL socket: " + e.getMessage(), e);
        }
    }

    private Socket createJSSSocket(Socket socket, String remoteHost, int port)
            throws IOException {

        JSSSocket jssSocket;

        SSLSocketFactory socketFactory;
        try {
            CryptoManager.getInstance();

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
            KeyManager[] kms = kmf.getKeyManagers();

            JSSTrustManager trustManager = new JSSTrustManager();
            trustManager.setHostname(remoteHost);
            trustManager.setCallback(connection.getCallback());
            trustManager.setEnableCertRevokeVerify(connection.getConfig().isCertRevocationVerify());

            TrustManager[] tms = new TrustManager[] { trustManager };

            SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
            ctx.init(kms, tms, null);

            socketFactory = ctx.getSocketFactory();

        } catch (Exception e) {
            throw new IOException("Unable to create SSL socket factory: " + e.getMessage(), e);
        }

        try {
            if (socket == null) {
                logger.debug("JSSSocketFactory: Creating new SSL socket");
                jssSocket = (JSSSocket) socketFactory.createSocket(
                        InetAddress.getByName(remoteHost),
                        port);

            } else {
                logger.debug("JSSSocketFactory: Creating SSL socket with existing socket");
                jssSocket = (JSSSocket) socketFactory.createSocket(
                        socket,
                        remoteHost,
                        port,
                        true);
            }

        } catch (Exception e) {
            throw new IOException("Unable to create SSL socket: " + e.getMessage(), e);
        }

        jssSocket.setUseClientMode(true);
        jssSocket.setListeners(Arrays.asList(createSocketListener()));
        jssSocket.startHandshake();
        return jssSocket;
    }

    private static void addSocketListener(SSLSocket socket) {
        socket.addSocketListener(createSocketListener());
    }

    private static SSLSocketListener createSocketListener() {
        return new SSLSocketListener() {

            @Override
            public void alertReceived(SSLAlertEvent event) {

                int intLevel = event.getLevel();
                SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                int intDescription = event.getDescription();
                SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                    logger.error(level + ": SSL alert received: " + description);
                }
            }

            @Override
            public void alertSent(SSLAlertEvent event) {

                int intLevel = event.getLevel();
                SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                int intDescription = event.getDescription();
                SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                    logger.error(level + ": SSL alert sent: " + description);
                }
            }

            @Override
            public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            }
        };
    }

    @Override
    public Socket connectSocket(
            int connTimeout,
            Socket socket,
            HttpHost host,
            InetSocketAddress remoteAddress,
            InetSocketAddress localAddress,
            HttpContext context)
            throws IOException,
            UnknownHostException {

        String hostname = null;
        int port = 0;

        if (host != null) {
            hostname = host.getHostName();
            port = host.getPort();
        } else if(remoteAddress != null) {
            hostname = remoteAddress.getHostName();
            port = remoteAddress.getPort();
        }

        if (socket == null) {
            socket = new Socket();
        }
        if (!socket.isConnected()) {
            if (localAddress != null) {
                socket.bind(localAddress);
            }
            if (remoteAddress != null) {
                socket.connect(remoteAddress, connTimeout);
            }
        }

        return createLayeredSocket(socket, hostname, port, context);
    }

}
