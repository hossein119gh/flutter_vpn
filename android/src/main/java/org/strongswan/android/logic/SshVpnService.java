package org.strongswan.android.logic;

import android.annotation.TargetApi;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;

import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnType;
import org.strongswan.android.logic.imc.ImcState;
import org.strongswan.android.utils.Constants;
import org.strongswan.android.utils.IPRange;
import org.strongswan.android.utils.IPRangeSet;
import org.strongswan.android.utils.SettingsWriter;
import org.strongswan.android.utils.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.SortedSet;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import io.xdea.flutter_vpn.R;

public class SshVpnService extends VpnService implements Runnable, VpnStateService.VpnStateListener {
    private static final String VPN_SERVICE_ACTION = "android.net.VpnService";
    public static final String DISCONNECT_ACTION = "org.strongswan.android.SshVpnService.DISCONNECT";
    private static final String NOTIFICATION_CHANNEL = "org.strongswan.android.SshVpnService.VPN_STATE_NOTIFICATION";
    private static final String TAG = "SshVpnService";
    public static final String LOG_FILE = "ssh.log";
    public static final String KEY_IS_RETRY = "retry";
    public static final int VPN_STATE_NOTIFICATION_ID = 1;
    private Session session;
    private Channel channel;
    private String mLogFile;
    private String mAppDir;
    private SshVpnService.BuilderAdapter mBuilderAdapter = new SshVpnService.BuilderAdapter();
    //private VpnProfileDataSource mDataSource;
    private Thread mConnectionHandler;
    private VpnProfile mCurrentProfile;
    private volatile String mCurrentCertificateAlias;
    private volatile String mCurrentUserCertificateAlias;
    private VpnProfile mNextProfile;
    private volatile boolean mProfileUpdated;
    private volatile boolean mTerminate;
    private volatile boolean mIsDisconnecting;
    private volatile boolean mShowNotification;

    private Handler mHandler;
    private VpnStateService mService;
    private final Object mServiceLock = new Object();
    ParcelFileDescriptor vpnInterface;
    /**
     * as defined in charonservice.h
     */
    static final int STATE_CHILD_SA_UP = 1;
    static final int STATE_CHILD_SA_DOWN = 2;
    static final int STATE_AUTH_ERROR = 3;
    static final int STATE_PEER_AUTH_ERROR = 4;
    static final int STATE_LOOKUP_ERROR = 5;
    static final int STATE_UNREACHABLE_ERROR = 6;
    static final int STATE_CERTIFICATE_UNAVAILABLE = 7;
    static final int STATE_GENERIC_ERROR = 8;
    private final ServiceConnection mServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceDisconnected(ComponentName name) {    /* since the service is local this is theoretically only called when the process is terminated */
            synchronized (mServiceLock) {
                mService = null;
            }
        }

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            synchronized (mServiceLock) {
                mService = ((VpnStateService.LocalBinder) service).getService();
            }
            /* we are now ready to start the handler thread */
            mService.registerListener(SshVpnService.this);
            mConnectionHandler.start();
        }
    };

    @Override
    public void onCreate() {
        mLogFile = getFilesDir().getAbsolutePath() + File.separator + LOG_FILE;
        mAppDir = getFilesDir().getAbsolutePath();

        /* handler used to do changes in the main UI thread */
        mHandler = new Handler(getMainLooper());

        /* use a separate thread as main thread for charon */
        mConnectionHandler = new Thread(this);
        /* the thread is started when the service is bound */
        bindService(new Intent(this, VpnStateService.class),
                mServiceConnection, Service.BIND_AUTO_CREATE);

        createNotificationChannel();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel;
            channel = new NotificationChannel(NOTIFICATION_CHANNEL, getString(R.string.permanent_notification_name),
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription(getString(R.string.permanent_notification_description));
            channel.setLockscreenVisibility(Notification.VISIBILITY_SECRET);
            channel.setShowBadge(false);
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }

    //    @Override
//    public int onStartCommand(Intent intent, int flags, int startId) {
//        vpnThread = new Thread(() -> {
//            try {
//                establishVpnConnection(intent);
//            } catch (IOException e) {
//                Log.e(TAG, "Error establishing VPN connection", e);
//            }
//        });
//        vpnThread.start();
//        return START_STICKY;
//    }
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            VpnProfile profile = null;
            boolean retry = false;

            if (VPN_SERVICE_ACTION.equals(intent.getAction()) ||
                    !DISCONNECT_ACTION.equals(intent.getAction())) {
                Bundle bundle = intent.getExtras();
                if (bundle != null) {
                    profile = new VpnProfile();
                    profile.setId(1);
                    profile.setUUID(UUID.randomUUID());
                    profile.setName(bundle.getString("Name"));
                    // Global
                    profile.setMTU(bundle.getInt("MTU", 1400));
                    profile.setUdpGw(bundle.getInt("UdpGw", 7300));
                    // Connection
                    profile.setGateway(bundle.getString("Server"));
                    if (bundle.containsKey("Port")) profile.setPort(bundle.getInt("Port"));
                    profile.setUsername(bundle.getString("Username"));
                    profile.setPassword(bundle.getString("Password"));
                    profile.setVpnType(VpnType.fromIdentifier(bundle.getString("VpnType")));
                    profile.setSelectedAppsHandling(VpnProfile.SelectedAppsHandling.SELECTED_APPS_DISABLE);
                    profile.setFlags(0);

                    retry = bundle.getBoolean(SshVpnService.KEY_IS_RETRY, false);
                }
            }
            if (DISCONNECT_ACTION.equals(intent.getAction())) {
                stopCurrentConnection();
            }
            if (profile != null && !retry) {    /* delete the log file if this is not an automatic retry */
                deleteFile(LOG_FILE);
            }
            setNextProfile(profile);
        }
        return START_NOT_STICKY;
    }

    private void setNextProfile(VpnProfile profile) {
        synchronized (this) {
            this.mNextProfile = profile;
            mProfileUpdated = true;
            notifyAll();
        }
    }

    @Override
    public void run() {
        while (true) {
            synchronized (this) {
                try {
                    while (!mProfileUpdated) {
                        wait();
                    }

                    mProfileUpdated = false;
                    stopCurrentConnection();
                    if (mNextProfile == null) {
                        setState(VpnStateService.State.DISABLED);
                        if (mTerminate) {
                            break;
                        }
                    } else {
                        mCurrentProfile = mNextProfile;
                        mNextProfile = null;

                        /* store this in a separate (volatile) variable to avoid
                         * a possible deadlock during deinitialization */
                        mCurrentCertificateAlias = mCurrentProfile.getCertificateAlias();
                        mCurrentUserCertificateAlias = mCurrentProfile.getUserCertificateAlias();

                        startConnection(mCurrentProfile);
                        mIsDisconnecting = false;

                        SimpleFetcher.enable();
                        addNotification();
                        mBuilderAdapter.setProfile(mCurrentProfile);

                        String host = mCurrentProfile.getGateway();
                        int port = mCurrentProfile.getPort();
                        String username = mCurrentProfile.getUsername();
                        String password = mCurrentProfile.getPassword();
                        int udpGw = mCurrentProfile.getUdpGw();
                        Log.e(TAG, "establishVpnConnection: #################");
                        Log.e(TAG, "establishVpnConnection: host: " + host);
                        Log.e(TAG, "establishVpnConnection: username: " + username);
                        Log.e(TAG, "establishVpnConnection: password: " + password);
                        Log.e(TAG, "establishVpnConnection: Port: " + port);
                        Log.e(TAG, "establishVpnConnection: udpGw: " + udpGw);
                        // Connect to SSH server and forward traffic
                        try (Socket socket = new Socket()) {
                            socket.connect(new InetSocketAddress(host, port), 5000);
                            // SSH connection logic
                            JSch jsch = new JSch();
                            session = jsch.getSession(username, host, port);

                            session.setPassword(password);
                            session.setConfig("StrictHostKeyChecking", "no");
                            session.connect();
                            channel = session.openChannel("shell");
                            channel.connect();
                            if (channel.isConnected()) {
                                Log.d(TAG, "establishVpnConnection: channel isConnected :) ");
                                setState(VpnStateService.State.CONNECTED);
                            } else {
                                Log.e(TAG, "establishVpnConnection: channel is not connect");
                                setState(VpnStateService.State.DISCONNECTING);
                            }
                            // Establish VPN interface
                            mBuilderAdapter.addAddress("10.0.0.2", 32);
                            mBuilderAdapter.addRoute("0.0.0.0", 0);
                            mBuilderAdapter.addDnsServer("8.8.8.8");
                            mBuilderAdapter.addDnsServer("8.8.4.4");
                            mBuilderAdapter.setMtu(1500);
                            vpnInterface = mBuilderAdapter.establishIntern();

                            //mode2 ------------------------------
//                            Builder builder = new Builder();
//                            builder.addAddress("10.0.0.2", 32)
//                                    .addRoute("0.0.0.0", 0)
//                                    .setSession("SSH VPN")
//                                    .setMtu(1500)
//                                    .addDnsServer("8.8.8.8")
//                                    .addDnsServer("8.8.4.4")
//                                    .establish();
//                            vpnInterface = builder.establish();

                            if (vpnInterface == null) {
                                Log.e(TAG, "establishVpnConnection: vpnInterface is null!!");
                                setError(VpnStateService.ErrorState.GENERIC_ERROR);
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

                        } catch (IOException | JSchException e) {
                            Log.e(TAG, "Error connecting to SSH server", e);
                            setError(VpnStateService.ErrorState.GENERIC_ERROR);
                            setState(VpnStateService.State.DISABLED);
                            mCurrentProfile = null;
                        }
                    }
                } catch (InterruptedException ex) {
                    stopCurrentConnection();
                    setState(VpnStateService.State.DISABLED);
                }
            }
        }
    }

    private void disconnect_SSH() {
        // Disconnect SSH session
        channel.disconnect();
        session.disconnect();
    }


//    private void establishVpnConnection(Intent intent) throws IOException {
//        String host = intent.getStringExtra("Server");
//        int port = intent.getIntExtra("Port", 22);
//        String username = intent.getStringExtra("Username");
//        String password = intent.getStringExtra("Password");
//        int udpGw = intent.getIntExtra("UdpGw", 7300);
//        Log.d(TAG, "establishVpnConnection: #################");
//        Log.d(TAG, "establishVpnConnection: host:"+host);
//        Log.d(TAG, "establishVpnConnection: username:"+username);
//        Log.d(TAG, "establishVpnConnection: password: "+password);
//        Log.d(TAG, "establishVpnConnection: Port: "+port);
//        Log.d(TAG, "establishVpnConnection: udpGw: "+udpGw);
//
//        // Connect to SSH server and forward traffic
//        try (Socket socket = new Socket()) {
//            socket.connect(new InetSocketAddress(host, port), 5000);
//            // SSH connection logic
//            JSch jsch = new JSch();
//            Session session = jsch.getSession(username, host, port);
//
//            session.setPassword(password);
//            session.setConfig("StrictHostKeyChecking", "no");
//            session.connect();
//            Channel channel = session.openChannel("shell");
//            channel.connect();
//            if (channel.isConnected())
//                Log.d(TAG, "establishVpnConnection: channel isConnected :) ");
//            else
//                Log.e(TAG, "establishVpnConnection: channel is not connect");
//            // Establish VPN interface
//            Builder builder = new Builder();
//            builder.addAddress("10.0.0.2", 32)
//                    .addRoute("0.0.0.0", 0)
//                    .setSession("SSH VPN")
//                    .setMtu(1500)
//                    .addDnsServer("8.8.8.8")
//                    .addDnsServer("8.8.4.4")
//                    .establish();
//            vpnInterface = builder.establish();
//            if(vpnInterface==null){
//                Log.e(TAG, "establishVpnConnection: vpnInterface is null!!" );
//                return;
//            }
//            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
//            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
//            channel.setInputStream(in);
//            channel.setOutputStream(out);
//            // Wait for channel to close
//            while (!channel.isClosed()) {
//                Log.d(TAG, "establishVpnConnection: ssh is open...");
//                try {
//                    TimeUnit.MILLISECONDS.sleep(100);
//                } catch (InterruptedException e) {
//                    Log.e(TAG, "Interrupted while waiting for channel to close", e);
//                }
//            }
//
//            // Disconnect SSH session
//            channel.disconnect();
//            session.disconnect();
//            Log.w(TAG, "establishVpnConnection:  channel and session is disconnected");
//        } catch (IOException | JSchException e) {
//            Log.e(TAG, "Error connecting to SSH server", e);
//        }
//    }

    private void startConnection(VpnProfile profile) {
        synchronized (mServiceLock) {
            if (mService != null) {
                mService.startConnection(profile);
            }
        }
    }

    private void stopCurrentConnection() {
        synchronized (this) {
            if (mNextProfile != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                mBuilderAdapter.setProfile(mNextProfile);
                mBuilderAdapter.establishBlocking();
            }

            if (mCurrentProfile != null) {
                setState(VpnStateService.State.DISCONNECTING);
                mIsDisconnecting = true;
                SimpleFetcher.disable();
                //deinitializeCharon();
                disconnect_SSH();
                Log.i(TAG, "ssh stopped");
                mCurrentProfile = null;
                removeNotification();
                if (mNextProfile == null) {    /* only do this if we are not connecting to another profile */
                    removeNotification();
                    mBuilderAdapter.closeBlocking();
                }
            }
        }
    }

    private void addNotification() {
        mHandler.post(() -> {
            mShowNotification = true;
            startForeground(VPN_STATE_NOTIFICATION_ID, buildNotification(false));
        });
    }

    /**
     * Build a notification matching the current state
     */
    private Notification buildNotification(boolean publicVersion) {
        VpnProfile profile = mService.getProfile();
        VpnStateService.State state = mService.getState();
        VpnStateService.ErrorState error = mService.getErrorState();
        String name = "";
        boolean add_action = false;

        if (profile != null) {
            name = profile.getName();
        }
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
                .setSmallIcon(R.drawable.ic_notification)
                .setCategory(NotificationCompat.CATEGORY_SERVICE)
                .setVisibility(publicVersion ? NotificationCompat.VISIBILITY_PUBLIC
                        : NotificationCompat.VISIBILITY_PRIVATE);
        int s = R.string.state_disabled;
        if (error != VpnStateService.ErrorState.NO_ERROR) {
            s = mService.getErrorText();
            builder.setSmallIcon(R.drawable.ic_notification_warning);
            builder.setColor(ContextCompat.getColor(this, R.color.error_text));

            if (!publicVersion && profile != null) {
                int retry = mService.getRetryIn();
                if (retry > 0) {
                    builder.setContentText(getResources().getQuantityString(R.plurals.retry_in, retry, retry));
                    builder.setProgress(mService.getRetryTimeout(), retry, false);
                }
            }
        } else {
            builder.setProgress(0, 0, false);

            switch (state) {
                case CONNECTING:
                    s = R.string.state_connecting;
                    builder.setSmallIcon(R.drawable.ic_notification_connecting);
                    builder.setColor(ContextCompat.getColor(this, R.color.warning_text));
                    add_action = true;
                    break;
                case CONNECTED:
                    s = R.string.state_connected;
                    builder.setColor(ContextCompat.getColor(this, R.color.success_text));
                    builder.setUsesChronometer(true);
                    add_action = true;
                    break;
                case DISCONNECTING:
                    s = R.string.state_disconnecting;
                    break;
            }
        }
        builder.setContentTitle(getString(s));
        if (!publicVersion) {
            if (error == VpnStateService.ErrorState.NO_ERROR) {
                builder.setContentText(name);
            }
            builder.setPublicVersion(buildNotification(true));
        }
        return builder.build();
    }

    private void removeNotification() {
        mHandler.post(() -> {
            mShowNotification = false;
            stopForeground(true);
        });
    }

    private void setState(VpnStateService.State state) {
        synchronized (mServiceLock) {
            if (mService != null) {
                mService.setState(state);
            }
        }
    }

    private void setError(VpnStateService.ErrorState error) {
        synchronized (mServiceLock) {
            if (mService != null) {
                mService.setError(error);
            }
        }
    }

    private void setImcState(ImcState state) {
        synchronized (mServiceLock) {
            if (mService != null) {
                mService.setImcState(state);
            }
        }
    }

    private void setErrorDisconnect(VpnStateService.ErrorState error) {
        synchronized (mServiceLock) {
            if (mService != null) {
                if (!mIsDisconnecting) {
                    mService.setError(error);
                }
            }
        }
    }

    public void updateStatus(int status) {
        switch (status) {
            case STATE_CHILD_SA_DOWN:
                if (!mIsDisconnecting) {
                    setState(VpnStateService.State.CONNECTING);
                }
                break;
            case STATE_CHILD_SA_UP:
                setState(VpnStateService.State.CONNECTED);
                break;
            case STATE_AUTH_ERROR:
                setErrorDisconnect(VpnStateService.ErrorState.AUTH_FAILED);
                break;
            case STATE_PEER_AUTH_ERROR:
                setErrorDisconnect(VpnStateService.ErrorState.PEER_AUTH_FAILED);
                break;
            case STATE_LOOKUP_ERROR:
                setErrorDisconnect(VpnStateService.ErrorState.LOOKUP_FAILED);
                break;
            case STATE_UNREACHABLE_ERROR:
                setErrorDisconnect(VpnStateService.ErrorState.UNREACHABLE);
                break;
            case STATE_CERTIFICATE_UNAVAILABLE:
                setErrorDisconnect(VpnStateService.ErrorState.CERTIFICATE_UNAVAILABLE);
                break;
            case STATE_GENERIC_ERROR:
                setErrorDisconnect(VpnStateService.ErrorState.GENERIC_ERROR);
                break;
            default:
                Log.e(TAG, "Unknown status code received");
                break;
        }
    }

    @Override
    public void stateChanged() {
        if (mShowNotification) {
            NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            manager.notify(VPN_STATE_NOTIFICATION_ID, buildNotification(false));
        }
    }

    /**
     * Adapter for VpnService.Builder which is used to access it safely via JNI.
     * There is a corresponding C object to access it from native code.
     */
    public class BuilderAdapter {
        private VpnProfile mProfile;
        private VpnService.Builder mBuilder;
        private SshVpnService.BuilderCache mCache;
        private SshVpnService.BuilderCache mEstablishedCache;
        private SshVpnService.BuilderAdapter.PacketDropper mDropper =
                new SshVpnService.BuilderAdapter.PacketDropper();

        public synchronized void setProfile(VpnProfile profile) {
            mProfile = profile;
            mBuilder = createBuilder(mProfile.getName());
            mCache = new SshVpnService.BuilderCache(mProfile);
        }

        private VpnService.Builder createBuilder(String name) {
            VpnService.Builder builder = new SshVpnService.Builder();
            builder.setSession(name);

            /* mark all VPN connections as unmetered (default changed for Android 10) */
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false);
            }
            return builder;
        }

        public synchronized boolean addAddress(String address, int prefixLength) {
            try {
                mCache.addAddress(address, prefixLength);
            } catch (IllegalArgumentException ex) {
                return false;
            }
            return true;
        }

        public synchronized boolean addDnsServer(String address) {
            try {
                mCache.addDnsServer(address);
            } catch (IllegalArgumentException ex) {
                return false;
            }
            return true;
        }

        public synchronized boolean addRoute(String address, int prefixLength) {
            try {
                mCache.addRoute(address, prefixLength);
            } catch (IllegalArgumentException ex) {
                return false;
            }
            return true;
        }

        public synchronized boolean addSearchDomain(String domain) {
            try {
                mBuilder.addSearchDomain(domain);
            } catch (IllegalArgumentException ex) {
                return false;
            }
            return true;
        }

        public synchronized boolean setMtu(int mtu) {
            try {
                mCache.setMtu(mtu);
            } catch (IllegalArgumentException ex) {
                return false;
            }
            return true;
        }

        private synchronized ParcelFileDescriptor establishIntern() {
            ParcelFileDescriptor fd;
            try {
                mCache.applyData(mBuilder);
                fd = mBuilder.establish();
                if (fd != null) {
                    closeBlocking();
                }
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
            if (fd == null) {
                return null;
            }
            /* now that the TUN device is created we don't need the current
             * builder anymore, but we might need another when reestablishing */
            mBuilder = createBuilder(mProfile.getName());
            mEstablishedCache = mCache;
            mCache = new SshVpnService.BuilderCache(mProfile);
            return fd;
        }

        public synchronized int establish() {
            ParcelFileDescriptor fd = establishIntern();
            return fd != null ? fd.detachFd() : -1;
        }

        @TargetApi(Build.VERSION_CODES.LOLLIPOP)
        public synchronized void establishBlocking() {
            /* just choose some arbitrary values to block all traffic (except for what's configured in the profile) */
            mCache.addAddress("172.16.252.1", 32);
            mCache.addAddress("fd00::fd02:1", 128);
            mCache.addRoute("0.0.0.0", 0);
            mCache.addRoute("::", 0);
            /* set DNS servers to avoid DNS leak later */
            mBuilder.addDnsServer("8.8.8.8");
            mBuilder.addDnsServer("2001:4860:4860::8888");
            /* use blocking mode to simplify packet dropping */
            mBuilder.setBlocking(true);
            ParcelFileDescriptor fd = establishIntern();
            if (fd != null) {
                mDropper.start(fd);
            }
        }

        public synchronized void closeBlocking() {
            mDropper.stop();
        }

        public synchronized int establishNoDns() {
            ParcelFileDescriptor fd;

            if (mEstablishedCache == null) {
                return -1;
            }
            try {
                Builder builder = createBuilder(mProfile.getName());
                mEstablishedCache.applyData(builder);
                fd = builder.establish();
            } catch (Exception ex) {
                ex.printStackTrace();
                return -1;
            }
            if (fd == null) {
                return -1;
            }
            return fd.detachFd();
        }

        private class PacketDropper implements Runnable {
            private ParcelFileDescriptor mFd;
            private Thread mThread;

            public void start(ParcelFileDescriptor fd) {
                mFd = fd;
                mThread = new Thread(this);
                mThread.start();
            }

            public void stop() {
                if (mFd != null) {
                    try {
                        mThread.interrupt();
                        mThread.join();
                        mFd.close();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    mFd = null;
                }
            }

            @Override
            public synchronized void run() {
                try {
                    FileInputStream plain = new FileInputStream(mFd.getFileDescriptor());
                    ByteBuffer packet = ByteBuffer.allocate(mCache.mMtu);
                    while (true) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {    /* just read and ignore all data, regular read() is not interruptible */
                            int len = plain.getChannel().read(packet);
                            packet.clear();
                            if (len < 0) {
                                break;
                            }
                        } else {    /* this is rather ugly but on older platforms not even the NIO version of read() is interruptible */
                            boolean wait = true;
                            if (plain.available() > 0) {
                                int len = plain.read(packet.array());
                                packet.clear();
                                if (len < 0 || Thread.interrupted()) {
                                    break;
                                }
                                /* check again right away, there may be another packet */
                                wait = false;
                            }
                            if (wait) {
                                Thread.sleep(250);
                            }
                        }
                    }
                } catch (ClosedByInterruptException | InterruptedException e) {
                    /* regular interruption */
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Cache non DNS related information so we can recreate the builder without
     * that information when reestablishing IKE_SAs
     */
    public class BuilderCache {
        private final List<IPRange> mAddresses = new ArrayList<>();
        private final List<IPRange> mRoutesIPv4 = new ArrayList<>();
        private final List<IPRange> mRoutesIPv6 = new ArrayList<>();
        private final IPRangeSet mIncludedSubnetsv4 = new IPRangeSet();
        private final IPRangeSet mIncludedSubnetsv6 = new IPRangeSet();
        private final IPRangeSet mExcludedSubnets;
        private final int mSplitTunneling;
        private final VpnProfile.SelectedAppsHandling mAppHandling;
        private final SortedSet<String> mSelectedApps;
        private final List<InetAddress> mDnsServers = new ArrayList<>();
        private int mMtu;
        private boolean mIPv4Seen, mIPv6Seen, mDnsServersConfigured;

        public BuilderCache(VpnProfile profile) {
            IPRangeSet included = IPRangeSet.fromString(profile.getIncludedSubnets());
            for (IPRange range : included) {
                if (range.getFrom() instanceof Inet4Address) {
                    mIncludedSubnetsv4.add(range);
                } else if (range.getFrom() instanceof Inet6Address) {
                    mIncludedSubnetsv6.add(range);
                }
            }
            mExcludedSubnets = IPRangeSet.fromString(profile.getExcludedSubnets());
            Integer splitTunneling = profile.getSplitTunneling();
            mSplitTunneling = splitTunneling != null ? splitTunneling : 0;
            VpnProfile.SelectedAppsHandling appHandling = profile.getSelectedAppsHandling();
            mSelectedApps = profile.getSelectedAppsSet();
            /* exclude our own app, otherwise the fetcher is blocked */
            switch (appHandling) {
                case SELECTED_APPS_DISABLE:
                    mSelectedApps.clear();
                    /* fall-through */
                case SELECTED_APPS_EXCLUDE:
                    mSelectedApps.add(getPackageName());
                    break;
                case SELECTED_APPS_ONLY:
                    mSelectedApps.remove(getPackageName());
                    break;
            }
            mAppHandling = appHandling;

            if (profile.getDnsServers() != null) {
                for (String server : profile.getDnsServers().split("\\s+")) {
                    try {
                        mDnsServers.add(Utils.parseInetAddress(server));
                        recordAddressFamily(server);
                        mDnsServersConfigured = true;
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    }
                }
            }

            /* set a default MTU, will be set by the daemon for regular interfaces */
            Integer mtu = profile.getMTU();
            mMtu = mtu == null ? Constants.MTU_MAX : mtu;
        }

        public void addAddress(String address, int prefixLength) {
            try {
                mAddresses.add(new IPRange(address, prefixLength));
                recordAddressFamily(address);
            } catch (UnknownHostException ex) {
                ex.printStackTrace();
            }
        }

        public void addDnsServer(String address) {
            /* ignore received DNS servers if any were configured */
            if (mDnsServersConfigured) {
                return;
            }

            try {
                mDnsServers.add(Utils.parseInetAddress(address));
                recordAddressFamily(address);
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
        }

        public void addRoute(String address, int prefixLength) {
            try {
                if (isIPv6(address)) {
                    mRoutesIPv6.add(new IPRange(address, prefixLength));
                } else {
                    mRoutesIPv4.add(new IPRange(address, prefixLength));
                }
            } catch (UnknownHostException ex) {
                ex.printStackTrace();
            }
        }

        public void setMtu(int mtu) {
            mMtu = mtu;
        }

        public void recordAddressFamily(String address) {
            try {
                if (isIPv6(address)) {
                    mIPv6Seen = true;
                } else {
                    mIPv4Seen = true;
                }
            } catch (UnknownHostException ex) {
                ex.printStackTrace();
            }
        }

        @TargetApi(Build.VERSION_CODES.LOLLIPOP)
        public void applyData(VpnService.Builder builder) {
            for (IPRange address : mAddresses) {
                builder.addAddress(address.getFrom(), address.getPrefix());
            }
            for (InetAddress server : mDnsServers) {
                builder.addDnsServer(server);
            }
            /* add routes depending on whether split tunneling is allowed or not,
             * that is, whether we have to handle and block non-VPN traffic */
            if ((mSplitTunneling & VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4) == 0) {
                if (mIPv4Seen) {    /* split tunneling is used depending on the routes and configuration */
                    IPRangeSet ranges = new IPRangeSet();
                    if (mIncludedSubnetsv4.size() > 0) {
                        ranges.add(mIncludedSubnetsv4);
                    } else {
                        ranges.addAll(mRoutesIPv4);
                    }
                    ranges.remove(mExcludedSubnets);
                    for (IPRange subnet : ranges.subnets()) {
                        try {
                            builder.addRoute(subnet.getFrom(), subnet.getPrefix());
                        } catch (
                                IllegalArgumentException e) {    /* some Android versions don't seem to like multicast addresses here,
                         * ignore it for now */
                            if (!subnet.getFrom().isMulticastAddress()) {
                                throw e;
                            }
                        }
                    }
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {    /* allow traffic that would otherwise be blocked to bypass the VPN */
                    builder.allowFamily(OsConstants.AF_INET);
                }
            } else if (mIPv4Seen) {    /* only needed if we've seen any addresses.  otherwise, traffic
             * is blocked by default (we also install no routes in that case) */
                builder.addRoute("0.0.0.0", 0);
            }
            /* same thing for IPv6 */
            if ((mSplitTunneling & VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6) == 0) {
                if (mIPv6Seen) {
                    IPRangeSet ranges = new IPRangeSet();
                    if (mIncludedSubnetsv6.size() > 0) {
                        ranges.add(mIncludedSubnetsv6);
                    } else {
                        ranges.addAll(mRoutesIPv6);
                    }
                    ranges.remove(mExcludedSubnets);
                    for (IPRange subnet : ranges.subnets()) {
                        try {
                            builder.addRoute(subnet.getFrom(), subnet.getPrefix());
                        } catch (IllegalArgumentException e) {
                            if (!subnet.getFrom().isMulticastAddress()) {
                                throw e;
                            }
                        }
                    }
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    builder.allowFamily(OsConstants.AF_INET6);
                }
            } else if (mIPv6Seen) {
                builder.addRoute("::", 0);
            }
            /* apply selected applications */
            if (mSelectedApps.size() > 0 &&
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                switch (mAppHandling) {
                    case SELECTED_APPS_EXCLUDE:
                        for (String app : mSelectedApps) {
                            try {
                                builder.addDisallowedApplication(app);
                            } catch (PackageManager.NameNotFoundException e) {
                                // possible if not configured via GUI or app was uninstalled
                            }
                        }
                        break;
                    case SELECTED_APPS_ONLY:
                        for (String app : mSelectedApps) {
                            try {
                                builder.addAllowedApplication(app);
                            } catch (PackageManager.NameNotFoundException e) {
                                // possible if not configured via GUI or app was uninstalled
                            }
                        }
                        break;
                    default:
                        break;
                }
            }
            builder.setMtu(mMtu);
        }

        private boolean isIPv6(String address) throws UnknownHostException {
            InetAddress addr = Utils.parseInetAddress(address);
            if (addr instanceof Inet4Address) {
                return false;
            } else if (addr instanceof Inet6Address) {
                return true;
            }
            return false;
        }
    }

    /**
     * Function called via JNI to determine information about the Android version.
     */
    private static String getAndroidVersion() {
        String version = "Android " + Build.VERSION.RELEASE + " - " + Build.DISPLAY;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            version += "/" + Build.VERSION.SECURITY_PATCH;
        }
        return version;
    }

    /**
     * Function called via JNI to determine information about the device.
     */
    private static String getDeviceString() {
        return Build.MODEL + " - " + Build.BRAND + "/" + Build.PRODUCT + "/" + Build.MANUFACTURER;
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
