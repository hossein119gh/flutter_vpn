package org.strongswan.android.logic;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class SshVpnService extends Service {
    public SshVpnService() {
    }

    @Override
    public IBinder onBind(Intent intent) {
        // TODO: Return the communication channel to the service.
        throw new UnsupportedOperationException("Not yet implemented");
    }
}