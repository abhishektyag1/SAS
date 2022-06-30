package client;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.*;

import pederson.PedersonShare;
import pederson.PedersonComm;

public class Client {
    private static SecureRandom random = new SecureRandom();

    private static Socket[] serverSockets;
    private static ObjectInputStream[] inStreams;
    private static ObjectOutputStream[] outStreams;
    private static int numServers;

    private static class IdentityFile implements Serializable {
        // An integer representing strong identity of the accuser
        public BigInteger identity;
        // Tickets and corresponding macs used to blindly prove identity to
        // escrows
        public BigInteger[] tickets;
        public byte[][] macs;
        // Indicates (tickets[i], macs[i]) has been used for i < numUsed
        public int numUsed;

        //Uid //make it an array and check each value of array later.
        public BigInteger[] Uid ;
        public void setMacs(Element[] eMacs) {
            assert(eMacs.length == tickets.length);
            macs = new byte[eMacs.length][];
            for (int i = 0; i < eMacs.length; ++i)
                macs[i] = eMacs[i].toBytes();
        }

        public Element[] getMacs() {
            assert(macs.length == tickets.length);
            Element[] res = new Element[macs.length];
            for (int i = 0; i < macs.length; ++i) {
                res[i] = PedersonShare.group.newOneElement();
                res[i].setFromBytes(macs[i]);
            }
            return res;
        }
    }

    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Arguments: [serverIp:port::...] register|file identity_file [threshold] [meta data] [allegation] [Unique Identifier R]");
            return;
        }
        if (!args[1].equals("register") && !args[1].equals("file")) {
            System.err.println("Unrecognized command '" + args[1] + "'. Command must be 'register' or 'file'.");
            return;
        }

        connectToServers(args[0]);
        System.out.println("Connected to servers.");

        try {
            if (args[1].equals("register"))
                register(17, args[2]);
            else {
                if (args.length != 6) {
                    System.err.println("Arguments: [serverIp:port::...] file identity_file [threshold] [meta data] [allegation]");
                    return;
                }
                fileAllegation(BigInteger.valueOf(Integer.parseInt(args[4])),
                        args[5],
                        BigInteger.valueOf(Integer.parseInt(args[3])),
                        args[2]);
            }
        }
        catch (IOException|ClassNotFoundException e) {
            System.err.println("Error while communicating with server.\n" + e.getMessage());
        }
    }

    private static void connectToServers(String addrString) {
        String[] addresses = addrString.split("::");
        String[] serverIps = new String[addresses.length];
        int[] serverPorts = new int[addresses.length];
        for (int i = 0; i < addresses.length; ++i) {
            serverIps[i] = addresses[i].split(":")[0];
            serverPorts[i] = Integer.parseInt(addresses[i].split(":")[1]);
        }

        serverSockets = new Socket[addresses.length];
        inStreams = new ObjectInputStream[addresses.length];

        outStreams = new ObjectOutputStream[addresses.length];

        for (int i = 0; i < addresses.length; ++i) {
            try {
                serverSockets[i] = new Socket(serverIps[i], serverPorts[i]);
                outStreams[i] = new ObjectOutputStream(serverSockets[i].getOutputStream());
                inStreams[i] = new ObjectInputStream(serverSockets[i].getInputStream());
            }
            catch (IOException e) { // TODO: be more specific
                System.err.println("Error while establishing connection with server. " + e.getMessage());
                System.exit(1);
            }
        }
        numServers = addresses.length;
    }

    private static void register(int numTickets, String identityFilename) throws IOException,ClassNotFoundException {
        // Choose our identity
        BigInteger identity = new BigInteger(64, random);
	//System.out.println("Identity is "+identity);

        // Choose keys
        BigInteger[] tickets = new BigInteger[numTickets];
        PedersonShare[][] ticketsShares = new PedersonShare[numTickets][];
        for (int i = 0; i < numTickets; ++i) {
            tickets[i] = new BigInteger(64, random);
            ticketsShares[i] = PedersonShare.shareValue(tickets[i], numServers/2, numServers);
        }

        // Send to servers
        int[] serverIndices = new int[numServers];
        for (int i = 0; i < numServers; ++i) {
            serverIndices[i] = (int)inStreams[i].readObject();
            outStreams[i].writeObject(new String("Register"));
            outStreams[i].writeObject(identity);
            outStreams[i].writeObject(numTickets);
            for (int j = 0; j < numTickets; ++j)
                outStreams[i].writeObject(ticketsShares[j][serverIndices[i]]);
            outStreams[i].flush();
        }
        //Element test = 

        // Receive MACs from servers
        Element[] macs = new Element[numTickets];
        for (int t = 0; t < numTickets; ++t) {
            // Receive exponentiated shares
            Element[][] expShares = new Element[numServers][];
            for (int i = 0; i < numServers; ++i) {
                byte[][] expShareBytes = (byte[][])inStreams[i].readObject();
                expShares[serverIndices[i]] = new Element[expShareBytes.length];
                for (int j = 0; j < expShareBytes.length; ++j) {
                    if (j < 2)
                        expShares[serverIndices[i]][j] = PedersonShare.groupG1.newOneElement();
                    else
                        expShares[serverIndices[i]][j] = PedersonShare.group.newOneElement();
                    expShares[serverIndices[i]][j].setFromBytes(expShareBytes[j]);
                }
            }
            macs[t] = PedersonComm.plaintextBilinearExponentiateRecv(expShares, numServers / 2, numServers);
        }
	System.out.println(" client mac is " + macs[0].toBytes());
	//Split the bigIntger at macs[0] into the 64 bit numbers array
	BigInteger splitUid = new BigInteger(macs[0].toBytes());
	String[] sUid = splitUid.toString(10).split("(?<=\\G.{45})");
	BigInteger[] Uid = new BigInteger[sUid.length];
	for(int i = 0 ; i< sUid.length ; i++) {
		Uid[i] = new BigInteger(sUid[i]);
		//System.out.println("The client UId is "+ Uid[i]);
	}
        // Write to file
        IdentityFile file = new IdentityFile();
        file.identity = identity;
        file.tickets = tickets;
        file.setMacs(macs);
        file.Uid = Uid;
        file.numUsed = 1;
        FileOutputStream outStream = new FileOutputStream(identityFilename);
        ObjectOutput outObjStream = new ObjectOutputStream(outStream);
        outObjStream.writeObject(file);
        outStream.close();
    }

    private static void fileAllegation(BigInteger metaData, String allegation, BigInteger revealThreshold, String identityFilename) throws IOException, ClassNotFoundException {
        // Read client data from file
        FileInputStream inStream = new FileInputStream(identityFilename);
        ObjectInput inObjStream = new ObjectInputStream(inStream);
        IdentityFile file = (IdentityFile)inObjStream.readObject();
        inObjStream.close();
        inStream.close();

        // Prepare encrypted allegation
        BigInteger aesKeyInt;
        BigInteger UniqueId = new BigInteger(64, random);
        byte[] allegationCipherText;
        try {
            aesKeyInt = new BigInteger(PedersonShare.modQ.bitLength(), random).mod(PedersonShare.modQ);
            byte[] unpaddedKey = aesKeyInt.toByteArray();
            byte[] paddedKey = new byte[16];
            for (int i = 0; i < 16; ++i) {
                if (i < unpaddedKey.length) paddedKey[i] = unpaddedKey[i];
                else paddedKey[i] = 0;
            }
            SecretKeySpec secretKey = new SecretKeySpec(paddedKey, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            allegationCipherText = cipher.doFinal(allegation.getBytes(StandardCharsets.UTF_8));
        }
        catch (Exception e) {
            System.err.println("Fatal error while encrypting allegation.\n" + e.getMessage());
            return;
        }
        System.out.println("The ticket 0 has been secret shared and the value is " + file.tickets[0]);
        PedersonShare[] rShares = PedersonShare.shareValue(file.tickets[0],numServers/2,numServers);
        PedersonShare[][] UidShares = new PedersonShare[file.Uid.length][];
        String Uid ="";
        for(int i = 0 ; i < file.Uid.length ; i++) {
        	Uid+= file.Uid[i].abs().toString(10);
        }
        System.out.println("Uid is " + Uid);
        System.out.println("meta data here is " + metaData);
        PedersonShare[][] metaDataShares = PedersonShare.shareBitValue(metaData,numServers/2,numServers);
        PedersonShare[] metaDataNum = PedersonShare.shareValue(metaData,numServers/2,numServers);
        PedersonShare[] secretKeyShares = PedersonShare.shareValue(aesKeyInt,numServers/2,numServers);
        PedersonShare[][] revealThresholdShares = PedersonShare.shareBitValue(revealThreshold,numServers/2,numServers);

        // Send to servers
        for (int i = 0; i < numServers; ++i) {
            int serverIndex = (int)inStreams[i].readObject();
            outStreams[i].writeObject(new String("Allege"));
            outStreams[i].writeObject(UniqueId);
            outStreams[i].writeObject(rShares[serverIndex]);
            outStreams[i].writeObject(Uid);
            outStreams[i].writeObject(file.tickets[file.numUsed]);
            outStreams[i].writeObject(file.macs[file.numUsed]);
            outStreams[i].writeObject(metaDataShares[serverIndex]);
            outStreams[i].writeObject(metaDataNum[serverIndex]);
            outStreams[i].writeObject(revealThresholdShares[serverIndex]);
            outStreams[i].writeObject(secretKeyShares[serverIndex]);
            outStreams[i].writeObject(allegationCipherText);
            outStreams[i].flush();
        }


        // Uid check
        boolean UidVerified = true;
        for (int i = 0; i < numServers; ++i)  UidVerified = UidVerified && (boolean)inStreams[i].readObject();
        if (!UidVerified)
            System.out.println("User is not authenticated.");


        // Receive from servers
        boolean identityApproved = true;
        for (int i = 0; i < numServers; ++i) {
		//System.out.println("Server Indexes " + (boolean)inStreams[i].readObject());
		identityApproved = identityApproved && (boolean)inStreams[i].readObject();
        }
        if (identityApproved)
            System.out.println("Identity approved.");
        else
            System.out.println("Identity not approved.");
            
        // Duplicity check 
        boolean duplicityVerified = true ;
        for(int i = 0 ; i < numServers ; ++i) duplicityVerified = duplicityVerified && (boolean)inStreams[i].readObject();
        if(!duplicityVerified)
        	System.out.println("You filed a duplicate allegation");

        // Store updated client data to file
        ++ file.numUsed;
        FileOutputStream outStream = new FileOutputStream(identityFilename);
        ObjectOutput outObjStream = new ObjectOutputStream(outStream);
        outObjStream.writeObject(file);
        outObjStream.close();
        outStream.close();
    }
}
