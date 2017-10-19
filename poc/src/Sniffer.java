import codec.UnifiTlv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Arrays;

public class Sniffer {

    private static final byte[] supersuper = {-23, 89, -68, 1};

    public static void main2(String[] args) throws IOException {
        InetAddress inetAddress = InetAddress.getByAddress("233.89.188.1", supersuper);
        MulticastSocket socket = new MulticastSocket(10001);
        socket.setReuseAddress(true);
        socket.joinGroup(inetAddress);

        TlvBox box = new TlvBox();
//        System.out.println(box.serialize());
//        box.putStringValue(0x02);

        Thread thread = new Thread(() -> {
            try {
                while (true) {
//                  byte[] bytes = new byte['È'];
//                  DatagramPacket datagramPacket = new DatagramPacket(bytes, bytes.length);
//                  socket.receive(datagramPacket);

                    DatagramPacket datagramPacket = new DatagramPacket(box.serialize(), box.serialize().length);
                    socket.send(datagramPacket);
                }
            } catch (Exception ex) {
                System.out.println(ex);
            }
        }, "discover");
        thread.start();
    }

    public static byte[] macToBytes(String mac) {
        String[] macAddressParts = mac.split(":");

        byte[] macAddressBytes = new byte[6];
        for(int i=0; i<6; i++){
            Integer hex = Integer.parseInt(macAddressParts[i], 16);
            macAddressBytes[i] = hex.byteValue();
        }

        return macAddressBytes;
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        byte[] macAddress = {0x00, 0x0d, (byte) 0xb9, 0x47, 0x65, (byte) 0xf9};
        byte[] ip = {0x00, 0x0d, (byte) 0xb9, 0x47, 0x65, (byte) 0xf9, (byte) 0xC0, (byte) 0xA8, 0x0, 0x1};
        byte[] mac = UnifiTlv.toTlv(UnifiTlv.MAC_ADDRESS, macAddress);
        byte[] count = UnifiTlv.toTlv((byte)0x12, ByteBuffer.allocate(4).putInt(1).array());
        byte[] anotherMac = UnifiTlv.toTlv((byte)0x13, macAddress);
        byte[] ipInfo = UnifiTlv.toTlv(UnifiTlv.IP_INFO, ip);
        byte[] username = UnifiTlv.toTlv(UnifiTlv.USERNAME, "UBN");
        byte[] firmware = UnifiTlv.toTlv(UnifiTlv.FIRMWARE_VERSION, "UGW4.v4.3.49.5001150");
        byte[] uptime = UnifiTlv.toTlv(UnifiTlv.UPTIME, ByteBuffer.allocate(4).putInt(458).array());
        byte[] hostname = UnifiTlv.toTlv(UnifiTlv.HOSTNAME, "PFSENSE");
        byte[] platform = UnifiTlv.toTlv(UnifiTlv.PLATFORM, "UGW3");
        byte[] otherPlatform = UnifiTlv.toTlv((byte)0x15, "UGW3");
        byte[] otherFirmware = UnifiTlv.toTlv((byte)0x1B, "4.3.49.5001150");
        byte[] otherOtherFirmware = UnifiTlv.toTlv((byte)0x16, "4.3.49.5001150");
        byte[] bytes = UnifiTlv.generate(2, 6, ipInfo, mac, uptime, hostname, platform, firmware, anotherMac, count, otherPlatform, otherFirmware, otherOtherFirmware);

        InetAddress inetAddress = InetAddress.getByAddress("233.89.188.1", supersuper);

        int i = bytes[0];
        System.out.println("Version " + i + " packet received of " + bytes.length + " bytes");
        int j = 1;
        byte b = bytes[j];
        System.out.println("Command: " + b);
        j++;

        byte[] arrayOfByte1 = new byte[2];
        System.arraycopy(bytes, j, arrayOfByte1, 0, arrayOfByte1.length);
        j += arrayOfByte1.length;
        int k = Sniffer.aaaa(arrayOfByte1);
        System.out.println("Data length: " + k);
        if (j + k > bytes.length) {
            throw new RuntimeException("Packet reports invalid data length, discarding...");
        }
        int m = k + 1 + 1 + 2;

        byte[] arrayOfByte2 = new byte[6];
        byte[] localObject3;
        byte[] localObject4;
        int i2 = -1;
        while (j < m) {
            int i3 = bytes[(j++)];
            System.arraycopy(bytes, j, arrayOfByte1, 0, arrayOfByte1.length);
            j += arrayOfByte1.length;
            int i4 = Sniffer.aaaa(arrayOfByte1);
            if (j + i4 > m)  {
                throw new RuntimeException("Invalid length (" + i4 + ") for item " + i3);
            }
            System.out.println("Item type: " + i3 + " length: " + i4);
            byte[] localObject2 = new byte[i4];
            System.arraycopy(bytes, j, localObject2, 0, localObject2.length);
            switch (i3) {
                case 3:
                    String str1 = new String(localObject2).trim();
                    System.out.println(" [" + str1 + "]");
                    break;
                case 1:
                    if (localObject2.length == 6) {
                        System.arraycopy(localObject2, 0, arrayOfByte2, 0, localObject2.length);
                        System.out.println(" [" + Sniffer.bbbbbbb(arrayOfByte2) + "]");
                    }
                    break;
                case 2:
                    if (localObject2.length == 10) {
                        localObject3 = new byte[6];
                        localObject4 = new byte[4];
                        System.arraycopy(localObject2, 0, localObject3, 0, localObject3.length);
                        System.arraycopy(localObject2, 6, localObject4, 0, localObject4.length);
                        InetAddress localInetAddress = null;
                        try {
                            localInetAddress = InetAddress.getByAddress((byte[]) localObject4);
                            System.out.println(" [" + Sniffer.bbbbbbb(localObject3) + ", " + localInetAddress.getHostAddress() + "]");
                        }
                        catch (UnknownHostException localUnknownHostException) {}
                    }
                    break;
                case 6:
                    System.out.println(" username: '" + new String((byte[])localObject2) + "'");
                    break;
                case 10:
                    System.out.println(" uptime: [" + Sniffer.aaaa(localObject2) + "]");
                    break;
                case 11:
                    System.out.println(" hostname: '" + new String((byte[])localObject2) + "'");
                    break;

                default:
                    System.out.println("\t TLV " + i3 + " data: [" + new String(localObject2).trim() + "]");
            }
            j += i4;
        }

        if ((i == 2) && (b == 8)) {
            System.out.println("coucou");
        }
        if (i == 2) {
            System.out.println("cicicicic");
        }
        if ((i == 2) && (b == 11) && (i2 == -1)) {
            System.out.println("sdfsdfsdfsfd");
        }
        if ((b == 6) || (b == 11) || (b == Byte.MIN_VALUE)) {
            System.out.println("qqqqqqqqqqqqq");
        }
        if ((b == 2) || (b == -126)) {
            System.out.println("psdpsdof");
        }
        DatagramPacket datagramPacket = new DatagramPacket(bytes, bytes.length, inetAddress, 10001);
        DatagramSocket socket = new DatagramSocket();

        while (true) {
            socket.send(datagramPacket);
            System.out.println(bytes.length);
            Thread.sleep(10000);
        }
    }

    public static int aaaa(byte[] paramArrayOfByte)
    {
        int i = 0;
        for (int j = 0; j < paramArrayOfByte.length; j++)
        {
            int k = (paramArrayOfByte[j] & 0xFF) << (paramArrayOfByte.length - 1 - j) * 8;
            i += k;
        }
        return i;
    }

    public static String bbbbbbb(byte[] paramArrayOfByte)
    {
        String str1 = null;
        if ((paramArrayOfByte != null) && (paramArrayOfByte.length > 5))
        {
            String[] arrayOfString = new String[paramArrayOfByte.length];
            for (int i = 0; i < paramArrayOfByte.length; i++)
            {
                String str2 = Integer.toHexString(paramArrayOfByte[i] & 0xFF);
                if (str2.length() == 1) {
                    str2 = "0" + str2;
                }
                arrayOfString[i] = str2.toUpperCase();
            }
            str1 = MessageFormat.format("{0}-{1}-{2}-{3}-{4}-{5}", (Object[])arrayOfString);
        }
        return str1;
    }
}
