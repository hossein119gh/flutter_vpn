package com.slipkprojects.ultrasshservice.util;

import android.content.Context;

import io.xdea.flutter_vpn.R;

/**
 * @author Skank3r
 */
public class SkProtect {

	private static final String TAG = SkProtect.class.getSimpleName();
	
	private static final String APP_BASE = "com.slipkprojects.sockshttp";
	
	// Assinatura da Google Play
	//private static final String APP_SIGNATURE = "XbhYZ4Bz/9F4cWLIDMg0wl/+jl8=\n";

	private static SkProtect mInstance;

	private Context mContext;
	
	public static void init(Context context) {
		if (mInstance == null) {
			mInstance = new SkProtect(context);

			// This method will print your certificate signature to the logcat.
			//AndroidTamperingProtectionUtils.getCertificateSignature(context);
		}
	}

	private SkProtect(Context context) {
		mContext = context;
	}
	
	/*public void tamperProtect() {
		AndroidTamperingProtection androidTamperingProtection = new AndroidTamperingProtection.Builder(mContext, APP_SIGNATURE)
			.installOnlyFromPlayStore(false) // By default is set to false.
			.build();

		if (!androidTamperingProtection.validate()) {
			throw new RuntimeException();
		}
	}*/
	
	public void simpleProtect() {
		if (!APP_BASE.equals(mContext.getPackageName().toLowerCase()) ||
				!mContext.getString(R.string.app_name).toLowerCase().equals("sockshttp")) {
			throw new RuntimeException();
		}
	}

	public static void CharlieProtect() {
		if (mInstance == null) return;
			
		mInstance.simpleProtect();
		
		// ative apenas ao enviar pra PlayStore
		//mInstance.tamperProtect();
	}
}
