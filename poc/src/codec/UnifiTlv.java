package codec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class UnifiTlv {

    public static final byte MAC_ADDRESS = 0x01;
    public static final byte IP_INFO = 0x02;
    public static final byte FIRMWARE_VERSION = 0x03;
    public static final byte USERNAME = 0x06;
    public static final byte UPTIME = 0xA;
    public static final byte HOSTNAME = 0xB;
    public static final byte PLATFORM = 0xC;

    public static byte[] toTlv(byte type, String value) throws IOException {
        byte[] bytesString = value.getBytes();
        int length = bytesString.length;

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(type);
        outputStream.write((byte) ((length >> 8) & 0xFF));
        outputStream.write((byte) (length & 0xFF));
        outputStream.write(bytesString);

        return outputStream.toByteArray();
    }

    public static byte[] toTlv(byte type, byte[] value) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(type);
        outputStream.write((byte) ((value.length >> 8) & 0xFF));
        outputStream.write((byte) (value.length & 0xFF));
        outputStream.write(value);

        return outputStream.toByteArray();
    }

    public static byte[] generate(int version, int command, byte[]... tlvs) throws IOException {
        int size = 0;

        for (byte[] tlv : tlvs) {
            size += tlv.length;
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(version);
        outputStream.write(command);
        outputStream.write(0x0);
        outputStream.write(size);
        for (byte[] tlv : tlvs) {
            outputStream.write(tlv);
        }

        return outputStream.toByteArray();
    }
}
