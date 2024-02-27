package org.strongswan.android.logic;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

public class SshVpnService extends VpnService {
    private static final String TAG = "SshVpnService";

    private Thread vpnThread;
    private ParcelFileDescriptor vpnInterface;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        vpnThread = new Thread(() -> {
            try {
                establishVpnConnection(intent);
            } catch (IOException e) {
                Log.e(TAG, "Error establishing VPN connection", e);
            }
        });
        vpnThread.start();
        return START_STICKY;
    }

    private void establishVpnConnection(Intent intent) throws IOException {
        String host = intent.getStringExtra("host");
        int port = intent.getIntExtra("port", 22);
        String username = intent.getStringExtra("username");
        String password = intent.getStringExtra("password");
        int udpGw = intent.getIntExtra("udpGw", 7300);

        // Connect to SSH server and forward traffic
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 5000);
            // SSH connection logic
            JSch jsch = new JSch();
            Session session = jsch.getSession(username, host, port);

            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();
            Channel channel = session.openChannel("shell");
            channel.connect();
            // Establish VPN interface
            Builder builder = new Builder();
            builder.addAddress("10.0.0.2", 32)
                    .addRoute("0.0.0.0", 0)
                    .setSession("SSH VPN")
                    .setMtu(1500)
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("8.8.4.4")
                    .establish();
            vpnInterface = builder.establish();

            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
            channel.setInputStream(in);
            channel.setOutputStream(out);
            // Wait for channel to close
            while (!channel.isClosed()) {
                try {
                    TimeUnit.MILLISECONDS.sleep(100);
                } catch (InterruptedException e) {
                    Log.e(TAG, "Interrupted while waiting for channel to close", e);
                }
            }
            // Disconnect SSH session
            channel.disconnect();
            session.disconnect();
        } catch (IOException | JSchException e) {
            Log.e(TAG, "Error connecting to SSH server", e);
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        try {
            vpnInterface.close();
        } catch (IOException e) {
            Log.e(TAG, "Error closing VPN interface", e);
        }
    }
}
