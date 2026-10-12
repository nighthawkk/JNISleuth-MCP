package com.dropper.net;

public class SocketBridge {
    static {
        System.loadLibrary("core-crypto");
    }

    public native int connectRaw(String hostAddress, int port);
    public native int sendFrame(int channelId, byte[] frameData, int offset, int length);
    public native void closeChannel(int channelId);

    public int invoke_connectRaw(String hostAddress, int port) {
        return this.connectRaw(hostAddress, port);
    }
}
