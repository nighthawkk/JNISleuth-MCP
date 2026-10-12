package com.dropper;

import android.content.Context;

public class Core {
    static {
        System.loadLibrary("core-crypto");
    }

    public native boolean initEngine(Context context, int configFlags);
    public native byte[] decryptPayload(byte[] encryptedData, String rc4KeyStr);
    public native String signC2Beacon(String beaconPayload, String deviceFingerprint);
    public static native byte[] deriveSessionKey(byte[] salt, byte[] seed, int rounds);
    public native byte[] packTelemetry(String endpoint, long timestampMs);

    public byte[] invoke_decryptPayload(byte[] encryptedData, String rc4KeyStr) {
        return this.decryptPayload(encryptedData, rc4KeyStr);
    }
}
