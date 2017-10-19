import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.UnknownHostException;
import java.util.Date;

public class Test {

    private static final byte[] supersuper = {-23, 89, -68, 1};

    public static void main(String[] args) throws IOException {
        InetAddress inetAddress = InetAddress.getByAddress("233.89.188.1", supersuper);
        MulticastSocket socket = new MulticastSocket(10001);
        socket.setReuseAddress(true);
        socket.joinGroup(inetAddress);

//        int k = 0;
//        byte i = 0x00;
//        byte j = 0x00;
//        while (k != 148) {
//            byte[] toto = {i, j};
//            k = Sniffer.aaaa(toto);
//
//            if (i % 128 == 0) {
//                i++;
//            } else {
//                i = 0;
//                j++;
//            }
//        }
//
//        System.out.println(1);
//        System.out.println(-108);


       while (true) {
            byte[] bytes = new byte[1024];
            DatagramPacket datagramPacket = new DatagramPacket(bytes, bytes.length);
            socket.receive(datagramPacket);
           System.out.println(new Date());

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
           int i1 = -1;
           int i2 = -1;
           byte[] arrayOfByte5 = new byte[6];
           String str5 = "";
           String str8 = null;
           String str9 = null;
           String str6 = "";
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
                    case 18:
                        i1 = Sniffer.aaaa((byte[])localObject2);
                        break;
                    case 19:
                        System.arraycopy(localObject2, 0, arrayOfByte5, 0, arrayOfByte5.length);
                        str9 = Sniffer.bbbbbbb(arrayOfByte5);
                        break;
                    case 21:
                        str6 = new String((byte[])localObject2);
                        break;
                    case 27:
                        str8 = new String((byte[])localObject2);
                        break;
                    case 22:
                        str5 = new String((byte[])localObject2);
                        break;
                    default:
                        System.out.println("\t TLV " + i3 + " data: [" + new String(localObject2).trim() + "]");
                }
                j += i4;
            }
        }
    }

}
