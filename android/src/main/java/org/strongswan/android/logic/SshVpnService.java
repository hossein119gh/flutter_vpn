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
        String host = intent.getStringExtra("Server");
        int port = intent.getIntExtra("Port", 22);
        String username = intent.getStringExtra("Username");
        String password = intent.getStringExtra("Password");
        int udpGw = intent.getIntExtra("UdpGw", 7300);
        Log.d(TAG, "establishVpnConnection: #################");
        Log.d(TAG, "establishVpnConnection: host:"+host);
        Log.d(TAG, "establishVpnConnection: username:"+username);
        Log.d(TAG, "establishVpnConnection: password: "+password);
        Log.d(TAG, "establishVpnConnection: Port: "+port);
        Log.d(TAG, "establishVpnConnection: udpGw: "+udpGw);

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
            if (channel.isConnected())
                Log.d(TAG, "establishVpnConnection: channel isConnected :) ");
            else
                Log.e(TAG, "establishVpnConnection: channel is not connect");
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
            if(vpnInterface==null){
                Log.e(TAG, "establishVpnConnection: vpnInterface is null!!" );
                return;
            }
            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
            channel.setInputStream(in);
            channel.setOutputStream(out);
            // Wait for channel to close
            while (!channel.isClosed()) {
                Log.d(TAG, "establishVpnConnection: ssh is open...");
                try {
                    TimeUnit.MILLISECONDS.sleep(100);
                } catch (InterruptedException e) {
                    Log.e(TAG, "Interrupted while waiting for channel to close", e);
                }
            }

            // Disconnect SSH session
            channel.disconnect();
            session.disconnect();
            Log.w(TAG, "establishVpnConnection:  channel and session is disconnected");
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
