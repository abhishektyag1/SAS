package server;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.lang.Math;
import java.util.concurrent.TimeoutException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import edu.biu.scapi.comm.twoPartyComm.LoadSocketParties;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.math.BigDecimal;
import java.math.BigInteger;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.multiPartyComm.SocketMultipartyCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import it.unisa.dia.gas.jpbc.*;

import pederson.PedersonShare;
import pederson.PedersonComm;

import mpcCrypto.PRF;
public class Server {
    
    // A fixed id assigned to each escrow. Important for proper MPC functioning
    //
    // It is initially set by an ordering on IP address and port number. After
    // setup it is permanently stored in a database.
    
    
    static int thisPartyId;
    private static SecureRandom random = new SecureRandom();
    // Database variables
    static Connection dbConnect;
    static Statement dbStatement;
    static Statement dbStatement2;

    // Crypto variables
    static PRF idMacPRF;
    static PRF idRevealPRF;
    static Channel[] channels;
    public static void main(String[] args) {
    	
        if (args.length != 4) {
            System.out.println("Arguments: port player.properties mysqlPath dbname");
            return;
        }
        connectToPeers(args[1]);
        try {
            connectToDB(args[2], args[3],channels);
        }
        catch(Exception e) {
            System.out.println("Error connecting to database. " + e.getMessage());
            e.printStackTrace(System.out);
            return;
        }

        int serverPort = Integer.parseInt(args[0]);

        ServerSocket serverSocket;
        try {
            serverSocket = new ServerSocket(serverPort);
        }
        catch (Exception e) { // TODO: be more specific
            System.err.println("Error: Could not bind to port " + serverPort);
            return;
        }

        System.out.println("Server setup complete.");

        while (true) {
            System.out.println("Waiting for clients.");
            ObjectInputStream inStream;
            ObjectOutputStream outStream;
            try {
                Socket clientSocket = serverSocket.accept();
                inStream = new ObjectInputStream(clientSocket.getInputStream());
                outStream = new ObjectOutputStream(clientSocket.getOutputStream());
            }
            catch (Exception e) { // TODO: be more specific
                System.err.println("Error while establishing connection with client.");
                continue;
            }

            try {
                outStream.writeObject(thisPartyId);
                outStream.flush();
                String action = (String)inStream.readObject();
                if (action.equals("Register")) {
                    BigInteger identity = (BigInteger)inStream.readObject();
                    int numTickets = (int)inStream.readObject();
                    for (int i = 0; i < numTickets; ++i) {
                        PedersonShare value = (PedersonShare)inStream.readObject();
                        Element[] result = idMacPRF.computeSend(value, channels);
                        byte[][] resBytes = new byte[result.length][];
                        for (int j = 0; j < result.length; ++j) resBytes[j] = result[j].toBytes();
                        outStream.writeObject(resBytes);
                        outStream.flush();

                        Element reveal = idRevealPRF.compute(value, channels);
                        dbStatement.executeUpdate("INSERT INTO Identities(identity, revealKey) VALUES('"
                                + encodeToBase64(identity) + "', '"
                                + encodeToBase64(reveal.toBytes()) + "')");
                    }
                }
                else if(action.equals("Allege")) {
                    BigInteger UniqueID = (BigInteger)inStream.readObject();
                    PedersonShare rShare = (PedersonShare)inStream.readObject(); //in
                    String UidRec =  (String) inStream.readObject();//in
                    BigInteger ticket = (BigInteger)inStream.readObject();//in
                    Element claimedMac = PedersonShare.groupG1.newOneElement();
                    claimedMac.setFromBytes((byte[])inStream.readObject());//in
                    PedersonShare[] metaDataShare = (PedersonShare[])inStream.readObject();//in
                    PedersonShare metaNum = (PedersonShare)inStream.readObject();//in
                    PedersonShare[] thresholdShare = (PedersonShare[])inStream.readObject();//in
                    PedersonShare textShare = (PedersonShare)inStream.readObject();//in
                    byte[] textCrypt = (byte[])inStream.readObject();//in
		    // UID check
                    boolean UidVerified =  true;
                    Element[] result = idMacPRF.computeSend(rShare, channels);
                    byte[][] resBytes = new byte[result.length][];
                    for (int j = 0; j < result.length; ++j) resBytes[j] = result[j].toBytes();
                    if (!PedersonComm.verifyUid(resBytes,thisPartyId, channels,new BigInteger(UidRec))) {
                        UidVerified = false;
                        System.out.println("Client Identity not approved");
                    }
                    long startshareNumber = System.nanoTime();
                    PedersonShare val = PedersonComm.shareNumber((BigInteger.ZERO), channels.length/2 , channels) ;
                    long endshareNumber =  System.nanoTime();
                    long resultTime = endshareNumber - startshareNumber ;
                    System.out.println("Time taken to share a number is "+ resultTime + " nano second") ;
                    long startBITS = System.nanoTime() ;
                    PedersonShare[] bitShare = BITS(val,channels.length/2,channels);
                    long endBITS = System.nanoTime();
                    resultTime = endBITS - startBITS ;
                    System.out.println("Time taken for bitSharing is " + resultTime + " nano second");
                    BigInteger valueOften = BigInteger.ZERO;
                    for(int i = 0 ;i < bitShare.length ; i++) {
                    	valueOften = valueOften.add(((BigInteger.valueOf(2)).pow(i)).multiply(PedersonComm.combineShares(bitShare[i],channels)));
                    }
                    System.out.println("i value is " + valueOften);
                    
                    outStream.writeObject(UidVerified);
                    outStream.flush();
                    if (!UidVerified)
                        continue;
                    // Calculate mac and verify claimedMac is correct
                    boolean identityVerified = idMacPRF.verify(ticket, claimedMac);

                    // Verify that this ticket hasn't been used before
                    ResultSet numMatchingTickets = dbStatement.executeQuery("SELECT count(identifier) FROM AllegationShares WHERE identifier='"
                            + encodeToBase64(claimedMac.toBytes()) + "'");

                    numMatchingTickets.next();
                    if (numMatchingTickets.getInt("count(identifier)") > 0) {
                        identityVerified = false;
                        System.out.println("Client tried to re-use tickets.");
                    }

                    // Send result of verification to client
                    outStream.writeObject(identityVerified);
                    outStream.flush();
                    if (!identityVerified)
                        continue;
                    // Do the duplicity check here and replace it with allegationShares table pid values.
                    boolean duplicityVerified = true;
                    BigInteger duplicatePrf = PedersonComm.convergeShares(UidRec,metaNum,channels);
                    ResultSet duplicateResultSet ;
                    String duplicateStatement = "Select count(*) from DuplicityTable where prf = '"+duplicatePrf+"'";
                    duplicateResultSet = dbStatement.executeQuery(duplicateStatement);
                    duplicateResultSet.next();
                    if (duplicateResultSet.getInt("count(*)") > 0) {
                        duplicityVerified = false;
                        System.out.println("duplicate allegation filled.");
                    }
                    // Send result of verification to client
                    outStream.writeObject(duplicityVerified);
                    outStream.flush();
                    if (!duplicityVerified)
                        continue;
                    //Dup insert
                    String dupInsert = "Insert into DuplicityTable( prf ) VALUES('"
                    		+ duplicatePrf +"')";
                    dbStatement.executeUpdate(dupInsert);
  
                    PedersonShare one = PedersonComm.shareNumber(BigInteger.ONE, channels.length/2, channels);
                    //Do the matching
                    String completePidString = "" ;
                    String completeThresholdString = "" ;
                    String[] choppedPidStrings ;
                    String[] choppedThresholdString ;
                    ResultSet perpetratorResultset ;
                    ResultSet allegationsResultSet ;
                    for(int i = 0 ; i < metaDataShare.length ; i++) completePidString += "." + encodeToBase64(metaDataShare[i]);
                    for(int i = 0 ; i < thresholdShare.length ; i++) completeThresholdString += "." + encodeToBase64(thresholdShare[i]);
                    
                    completePidString = completePidString.substring(1);
                    completeThresholdString = completeThresholdString.substring(1);
                    System.out.println("The length of pid is " + completePidString.length());
                    String insertAllegation = "Insert into AllegationsTable( serial_number, identifier, R, Uid, Pid,revealedFlag, threshold, complaint, secretKey ) VALUES('"
                    		+ UniqueID
                    		+ "', '" + encodeToBase64(claimedMac.toBytes())
                    		+ "', '" + encodeToBase64(rShare)
                    		+ "', '" + UidRec
                    		+ "', '" + completePidString
                    		+ "', '" + encodeToBase64(one)
                    		+ "', '" + completeThresholdString
                    		+ "', '" + encodeToBase64(textCrypt)
                    		+ "', '" + encodeToBase64(textShare) + "')";
                    dbStatement.executeUpdate(insertAllegation);
                    String allegationSelectStatement = null;
                    allegationSelectStatement = "select serial_number, identifier, R, Uid, Pid,revealedFlag, threshold, complaint, secretKey from AllegationsTable order by serial_number";
                    PedersonShare flag = PedersonComm.shareNumber(BigInteger.ZERO, channels.length/2, channels);
                    for(int mx = 5  ; mx >= 0 ; mx--){
                    	PedersonShare count = PedersonComm.shareNumber(BigInteger.ZERO, channels.length/2, channels);
                    	allegationsResultSet = dbStatement.executeQuery(allegationSelectStatement);
                    	PedersonShare[] mxBits = PedersonComm.getValueShares(BigInteger.valueOf(mx),channels.length/2, channels);
                    	while(allegationsResultSet.next()) {//find revealableSetCount
                    		completePidString = allegationsResultSet.getString("Pid");
                    		completeThresholdString = allegationsResultSet.getString("threshold");
                    		choppedPidStrings = completePidString.split("(\\.)");
                    		choppedThresholdString = completeThresholdString.split("(\\.)");
                    		PedersonShare[] Pid_i = new PedersonShare[choppedPidStrings.length];
                    		PedersonShare[] t_i = new PedersonShare[choppedThresholdString.length];
                    		for(int i = 0 ; i < choppedPidStrings.length ; i++) 
                    			Pid_i[i] = (PedersonShare)decodeFromBase64(choppedPidStrings[i]);
                    		for(int i = 0 ; i < choppedThresholdString.length ; i++) 
                    			t_i[i] = (PedersonShare)decodeFromBase64(choppedThresholdString[i]);
                    		if(Pid_i.length != metaDataShare.length) continue ;
                    		PedersonShare chk1 = BitLT(Pid_i,metaDataShare,channels); // Equal if (BitLT(x,y) || BitLT(y,x)) == 0
                    		PedersonShare chk2 = BitLT(metaDataShare,Pid_i,channels);
                    		PedersonShare chk3 = chk1.add(chk2) ;
                    		PedersonShare chk4 = one.subtract(chk3);
                    		PedersonShare chk5 = BitLT(mxBits,t_i,channels);
                    		PedersonShare chk6 = one.subtract(chk5);
                    		PedersonShare chk = PedersonComm.multiply(chk4,chk6,channels);
                    		System.out.println("for mx " + mx + " final check is " + PedersonComm.combineShares(chk,channels));
                    		PedersonShare a = PedersonComm.multiply(count,one.subtract(chk),channels);
                    		PedersonShare b = PedersonComm.multiply(count.add(one),chk,channels) ;
                    		count = a.add(b) ;
                    		System.out.println("Count " + PedersonComm.combineShares(count,channels));
                    		//PedersonShare[] countInBits = BITS(count,channels.length/2, channels); //initialize with 1
                    		//PedersonShare[] mxInBits = PedersonComm.getValueShares(BigInteger.valueOf(mx+1),channels.length/2, channels);
                    	}
                    	if(PedersonComm.combineShares(PedersonComm.piCompare(mx,count,channels),channels).compareTo(BigInteger.ZERO) == 0){
                    		System.out.println("Should enter only when count > mx " );
                    		allegationsResultSet = dbStatement.executeQuery(allegationSelectStatement);
                    		while(allegationsResultSet.next()){//reveal one by one
                    			completePidString = allegationsResultSet.getString("Pid");
                    			completeThresholdString = allegationsResultSet.getString("threshold");
                    			choppedPidStrings = completePidString.split("(\\.)");
                    			choppedThresholdString = completeThresholdString.split("(\\.)");
                    			PedersonShare[] Pid_i = new PedersonShare[choppedPidStrings.length];
                    			PedersonShare[] t_i = new PedersonShare[choppedThresholdString.length];
                    			for(int i = 0 ; i < choppedPidStrings.length ; i++) 
                    				Pid_i[i] = (PedersonShare)decodeFromBase64(choppedPidStrings[i]);
                    			for(int i = 0 ; i < choppedThresholdString.length ; i++) 
                    				t_i[i] = (PedersonShare)decodeFromBase64(choppedThresholdString[i]);
                    			if(Pid_i.length != metaDataShare.length) continue ;
                    			long startBitLT = System.nanoTime();
                    			PedersonShare chk1 = BitLT(Pid_i,metaDataShare,channels);
                    			long endBitLT = System.nanoTime();
                    			resultTime = startBitLT - endBitLT;
                    			System.out.println("Time taken for comparison is " + resultTime + " nano second" );
                    			PedersonShare chk2 = BitLT(metaDataShare,Pid_i,channels);
                    			PedersonShare chk3 = chk1.add(chk2) ;
                    			PedersonShare chk4 = one.subtract(chk3);
                    			PedersonShare chk5 = BitLT(mxBits,t_i,channels);
                    			PedersonShare chk6 = one.subtract(chk5);
                    			PedersonShare chk7 = (PedersonShare)decodeFromBase64(allegationsResultSet.getString("revealedFlag"));
                    			System.out.println("chk6 is " + PedersonComm.combineShares(chk6,channels) +
                    				 " and chk4 " + PedersonComm.combineShares(chk4,channels) + " and chk7 " + 
                    				 	PedersonComm.combineShares(chk7,channels)  ) ;
                    			PedersonShare chk = PedersonComm.multiply(chk6,chk4,channels);
                    			chk = PedersonComm.multiply(chk,chk7,channels);
                    			System.out.println("final check is " + PedersonComm.combineShares(chk,channels));
                    			if(PedersonComm.combineShares(chk,channels).compareTo(BigInteger.ONE) == 0){
                    				String sr = allegationsResultSet.getString("serial_number") ;
                    				System.out.println("User: " +PedersonComm.combineShares((PedersonShare)decodeFromBase64(allegationsResultSet.getString("R")),channels));
                    				//UPDATE FLAG
                    				String updateStatement = "update AllegationsTable set revealedFlag = '" + encodeToBase64(flag) + "' where serial_number = '"+sr +"'" ;
                    				//System.out.println(updateStatement);
                    				dbStatement2.executeUpdate(updateStatement);
                    			}
                    		}
                    	}
                    }
                }
                else {
                    System.err.println("Unrecognized command '" + action +"'.");
                    continue;
                }
            }
            catch (IOException|ClassNotFoundException|SQLException e) {
                System.err.println("Error while processing request.\n" + e.getMessage());
            }
        }
    }



    private static Object decodeFromBase64(String str) throws IOException,ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(str);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object result = null;                             
        try {
            result = ois.readObject();
        }
        catch (Exception e) {
           System.err.println("Let's find out \n" + e.getMessage());
        }
        ois.close();
        return result;
    }

    private static String encodeToBase64(Object obj) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        try {
            oos.writeObject(obj);
        }
        catch (Exception e) {
            throw new RuntimeException("Could not serialize object. " + e.getMessage());
        }
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    
    private static void connectToPeers(String propertiesFileName) {
        // Setup communication
       
        LoadSocketParties loadParties = new LoadSocketParties(propertiesFileName);
        List<PartyData> partiesList = loadParties.getPartiesList();
        SocketPartyData[] parties = partiesList.toArray(new SocketPartyData[0]);
        SocketMultipartyCommunicationSetup commSetup = new SocketMultipartyCommunicationSetup(partiesList);
        long timeoutInMs = 60000;  //The maximum amount of time we are willing to wait to set a connection.
        HashMap<PartyData, Object> connectionsPerParty = new HashMap<PartyData, Object>();
        for (int i = 1; i < parties.length; ++i)
            connectionsPerParty.put(parties[i], 2);
	Map<PartyData, Map<String, Channel>> connections  ;
        try {
            connections = commSetup.prepareForCommunication(connectionsPerParty, timeoutInMs);
        }
        catch (TimeoutException e) {
            System.err.println("Error: Timed out. Could not establish connection.");
            return ;
        }

        // Create channels array
        SocketPartyData thisParty = parties[0];
        thisPartyId = -1;
        Arrays.sort(parties, new Comparator<SocketPartyData>() {
            @Override
            public int compare(SocketPartyData o1, SocketPartyData o2) {
                return o1.getPort() < o2.getPort() ? -1 : (o1.getPort() == o2.getPort() ? 0 : 1);
            }
        });
        channels = new Channel[parties.length];
        for (int i = 0; i < parties.length; ++i) {
            if (parties[i] == thisParty) {
                channels[i] = null;
                thisPartyId = i;
                continue;
            }
            channels[i] = connections.get(parties[i]).values().iterator().next();

        }
    }
    /**
     * Connects to MySQL database. If not already present, creates database and
     * some tables which are populated with appropriate initial values.
     */
    private static void connectToDB(String address, String dbname,Channel[] channels) throws SQLException,IOException,ClassNotFoundException {
        //Class.forName("com.mysql.jdbc.Driver");
        dbConnect = DriverManager.getConnection(address);
        dbStatement = dbConnect.createStatement();
        dbStatement2 = dbConnect.createStatement();

        dbname = "escrow" + (thisPartyId + 1);
        // Use database if present. Else create
        ResultSet databases = dbStatement.executeQuery("SHOW DATABASES");
        boolean databaseExists = false;
        while (databases.next()) {
            if(databases.getString("Database").equals(dbname)) {
                databaseExists = true;
                break;
            }
        }
        if (!databaseExists)
            dbStatement.executeUpdate("CREATE DATABASE " + dbname);
        dbStatement.executeUpdate("USE " + dbname);
        databases.close();

        // If config table doesn't exist, create it. Else read configs
        ResultSet tables = dbStatement.executeQuery("SHOW TABLES");
        boolean configTableExists = false;
        while (tables.next()) {
            if (tables.getString("Tables_in_" + dbname).equals("Config")) {
                configTableExists = true;
                ResultSet configTable = dbStatement.executeQuery("SELECT name, intVal, charVal FROM Config");
                thisPartyId = -1;
                idMacPRF = idRevealPRF = null;

                System.out.println("Reading configs from database");
                while (configTable.next()) {
                    if (configTable.getString("name").equals("thisPartyId"))
                        thisPartyId = configTable.getInt("intVal");
                    else if (configTable.getString("name").equals("idMacPRF"))
                        idMacPRF = (PRF)decodeFromBase64(configTable.getString("charVal"));
                    else if (configTable.getString("name").equals("idRevealPRF"))
                        idRevealPRF = (PRF)decodeFromBase64(configTable.getString("charVal"));
                    else
                        System.err.println("Unrecognized config row '" + configTable.getString("name"));
                }
                if (thisPartyId == -1)
                    throw new RuntimeException("Could not load 'thisPartyId' from config table.");
                break;
            }
        }
        if (!configTableExists) {
            System.out.println("Initializing database.");
            idMacPRF = new PRF(channels.length / 2, channels);
            idRevealPRF = new PRF(channels.length / 2, channels);
            System.out.println("PRFs initialized");

            dbStatement.executeUpdate("CREATE TABLE Config(name CHAR(20) PRIMARY KEY, intVal INT, charVal VARCHAR(4000))");
            dbStatement.executeUpdate("INSERT INTO Config(name, intVal) VALUES('thisPartyId', '" + thisPartyId + "')");
            dbStatement.executeUpdate("INSERT INTO Config(name, charVal) VALUES('idMacPRF', '" + encodeToBase64(idMacPRF) + "')");
            System.out.println("MacPRF written to db "+idMacPRF+" -------------- and revealPRF "+idRevealPRF);

            dbStatement.executeUpdate("INSERT INTO Config(name, charVal) VALUES('idRevealPRF', '" + encodeToBase64(idRevealPRF) + "')");

            // TODO(venkat): make appropriate fields 'not null'
            dbStatement.executeUpdate("create table DuplicityTable( prf varchar(16000) NOT NULL)");
            dbStatement.executeUpdate("CREATE TABLE Identities(identity VARCHAR(4000), revealKey VARCHAR(4000))");
            dbStatement.executeUpdate("create table AllegationsTable(serial_number varchar(50) NOT NULL,	identifier varchar(3000) NOT NULL,	R varchar(4000) NOT NULL,	Uid varchar(4000) NOT NULL,	Pid TEXT(65000) NOT NULL,	revealedFlag varchar(4000) NOT NULL,	complaint varchar(16000) ,	threshold TEXT(4000) NOT NULL,	secretKey varchar(4000) NOT NUll)");
        }
    }

    private static PedersonShare[] BITS(PedersonShare a,int threshold ,Channel[] channels) throws IOException{
    	PedersonShare zero = PedersonComm.shareNumber(BigInteger.ZERO, channels.length/2 , channels);
    	System.out.println("A is " + PedersonComm.combineShares(a,channels)) ;
    	BigInteger p = PedersonShare.modQ ;
    	int l = p.bitLength() ;
    	System.out.println("l value is " + l ) ;
    	PedersonShare[] bBshares  = new PedersonShare[l] ;
    	bBshares[l-1] = zero ;
    	for(int i = 0 ; i < l - 1 ; i++)  bBshares[i] = PedersonComm.RAN2(threshold,channels);
    	PedersonShare[] pBshares = PedersonComm.getValueShares(p,threshold,channels); 
    	PedersonShare bpShares = zero;
    	for(int i = 0 ; i < l ; i++) bpShares = bpShares.addConstant(((BigInteger.valueOf(2)).pow(i)).multiply(PedersonComm.combineShares(bBshares[i],channels)));
    	System.out.println(" b value is " + PedersonComm.combineShares(bpShares,channels));
    	PedersonShare a_b = a.subtract(bpShares) ;
    	BigInteger c = PedersonComm.combineShares(a_b,channels);
    	System.out.println("c value is " + c ) ;
    	PedersonShare[] cBshares = PedersonComm.getValueShares(c,threshold,channels); 
    	long startBitAdd = System.nanoTime(); 
    	PedersonShare[] dBshares = BitAdd(cBshares,bBshares,channels) ;
    	long endBitAdd =  System.nanoTime();
    	long resultTime = endBitAdd - startBitAdd ;
    	System.out.println("Time taken to sum two 160 bits numbers is "+ resultTime + " nano second") ;
    	BigInteger valueOften = BigInteger.ZERO ;
		for(int j = 0 ; j < dBshares.length ; j++){
		 valueOften = valueOften.add(((BigInteger.valueOf(2)).pow(j)).multiply(PedersonComm.combineShares(dBshares[j],channels)));
        }
        System.out.println( "d is " + valueOften);
    	PedersonShare qpShares = BitLT(pBshares,dBshares,channels);
    	System.out.println("q bit is " + PedersonComm.combineShares(qpShares,channels));
    	BigInteger f = ((BigInteger.valueOf(2)).pow(l)) ;
    	System.out.println("2^l is " + f ) ;
    	f = f.subtract(p);
    	System.out.println("f value is " + f ) ;
    	PedersonShare[] fBits = PedersonComm.getValueShares(f,threshold,channels); 
    	PedersonShare[] gBshares = new PedersonShare[fBits.length] ;
    	for(int i = 0 ;i < fBits.length ; i++) 
    		 gBshares[i] =  PedersonComm.multiply(qpShares,fBits[i],channels); 
    	valueOften = BigInteger.ZERO ;
	for(int j = 0 ; j < gBshares.length ; j++){
		 valueOften = valueOften.add(((BigInteger.valueOf(2)).pow(j)).multiply(PedersonComm.combineShares(gBshares[j],channels)));
        }
        System.out.println( "g is " + valueOften);
    	PedersonShare[] hBshares = BitAdd(dBshares,gBshares,channels); 
    	valueOften = BigInteger.ZERO ;
	for(int j = 0 ; j < hBshares.length ; j++){
		 valueOften = valueOften.add(((BigInteger.valueOf(2)).pow(j)).multiply(PedersonComm.combineShares(hBshares[j],channels)));
        }
    	PedersonShare[] aBshares = new PedersonShare[hBshares.length - 2] ;
    	for(int i = 0 ; i < aBshares.length ; i ++) aBshares[i] = hBshares[i] ;
    	return aBshares ;
    }

    private static PedersonShare[] BitAdd(PedersonShare[] aBshares , PedersonShare[] bBshares,Channel[] channels)throws IOException{
    	PedersonShare[] a = null ;
    	PedersonShare[] b = null ;
    	if(aBshares.length > bBshares.length) {
    		a = aBshares ;
    		b = new PedersonShare[aBshares.length] ;
    		int i ;
    		for(i = 0 ; i < bBshares.length ; i++) b[i] = bBshares[i] ;
    		for(; i < aBshares.length ; i++) b[i] = PedersonComm.shareNumber(BigInteger.ZERO, channels.length/2 , channels) ;
    	}else if(bBshares.length > aBshares.length) {
    		b = bBshares ;
    		a = new PedersonShare[bBshares.length] ;
    		int i ;
    		for(i = 0 ; i < aBshares.length ; i++) a[i] = aBshares[i] ;
    		for(; i < bBshares.length ; i++) a[i] = PedersonComm.shareNumber(BigInteger.ZERO, channels.length/2 , channels) ;
    	}else{
    		a = aBshares ;
    		b = bBshares ;
    	}
    	
    	for(int i = 0 ; i< a.length ; i++){
    		BigInteger text = PedersonComm.combineShares(a[i],channels) ;
    		if(thisPartyId==1) System.out.print(text);
    	} 
    	System.out.println();
    	for(int i = 0 ; i< b.length ; i++){
    		BigInteger text = PedersonComm.combineShares(b[i],channels) ;
    		if(thisPartyId==1) System.out.print(text);
    	}
    	System.out.println();
    	PedersonShare[] cBshares = carries(a,b,channels);
    	PedersonShare[] dBshares = new PedersonShare[cBshares.length + 1 ] ;
    	int l = cBshares.length ;
    	dBshares[0] = (a[0].add(b[0])).subtract(cBshares[0].constMultiply(BigInteger.valueOf(2)));
    	dBshares[l] = cBshares[l-1] ;
    	for(int i = 1 ; i < l ; i++) 
    		dBshares[i] = ((a[i].add(b[i])).add(cBshares[i-1])).subtract(cBshares[i].constMultiply(BigInteger.valueOf(2)));
    	System.out.println("h");
    	for(int i = 1 ; i < l ; i++){
    		BigInteger text = PedersonComm.combineShares(dBshares[i],channels) ;
    		if(thisPartyId==1) System.out.print(text);
    	}
    	System.out.println("done");
    	return dBshares ;
    }
    
    private static PedersonShare[] carries(PedersonShare[] aBshares , PedersonShare[] bBshares,Channel[] channels)throws IOException{
    	int l = bBshares.length ;
    	PedersonShare[] sBshares = new PedersonShare[l] ;
    	PedersonShare[] pBshares = new PedersonShare[l] ;
    	PedersonShare[] kBshares = new PedersonShare[l] ;
    	PedersonShare[][] eBshares = new PedersonShare[l][3] ;
    	for(int i = 0 ; i < l ; i++) {
    		sBshares[i] = PedersonComm.multiply(aBshares[i],bBshares[i],channels);
    		pBshares[i] = (aBshares[i].add(bBshares[i])).subtract(sBshares[i].constMultiply(BigInteger.valueOf(2)));
    		kBshares[i] = ((sBshares[i].constMultiply(BigInteger.valueOf(-1))).addConstant(1)).subtract(pBshares[i]);
    		eBshares[i][0] = sBshares[i] ;
    		eBshares[i][1] = pBshares[i] ;
    		eBshares[i][2] = kBshares[i] ;
    	}
    	System.out.println("PREo started") ;
    	PedersonShare[][] fBshares = PREo(eBshares,channels) ;
    	System.out.println("PREo completed") ;
    	for(int i = 0 ; i < l ; i++ ) sBshares[i] = fBshares[i][0] ;
    	return sBshares ;
    }
    private static PedersonShare[][] PREo(PedersonShare[][] eBshares,Channel[] channels)throws IOException{
    	try {
		int l = eBshares.length ;
    		PedersonShare[] aBshares = new PedersonShare[l] ;
    		PedersonShare[] bBshares = new PedersonShare[l] ;
    		PedersonShare[] cBshares = new PedersonShare[l] ;
    		PedersonShare[][] result = new PedersonShare[l][3] ;
    		PedersonShare[][] qBshares = new PedersonShare[l][l] ;
    		PedersonShare[] c = new PedersonShare[l] ;
    		PedersonShare[] b = new PedersonShare[l] ;
    		qBshares[0][0] = eBshares[0][1] ;
    		c[0] = eBshares[0][2] ;
    		b[0] = eBshares[0][1] ;
    		for(int i = 1 ; i < l ; i ++) {
    			for(int j = 0 ; j < i ; j ++) {
    				qBshares[i][j] = PedersonComm.multiply(qBshares[i-1][j],eBshares[i][1],channels); 
    			}
    			qBshares[i][i] = eBshares[i][1] ;
    			PedersonShare temp = eBshares[i][2] ;
    			for(int j = 0 ; j < i ; j++) temp = temp.add(PedersonComm.multiply(qBshares[i][j+1],eBshares[j][2],channels));
    			c[i] = temp ; 
    			b[i] = PedersonComm.multiply(b[i-1],eBshares[i][1],channels); 
    			System.out.println(i);
    		}
    		result[0][1] = b[0] ; //b
    		result[0][2] = c[0] ; //c
    		result[0][0] = ((result[0][1].constMultiply(BigInteger.valueOf(-1))).addConstant(1)).subtract(result[0][2]) ; //a
    		for(int i = 1 ; i < l ; i ++){
    			result[i][1] = b[i] ;
    			result[i][2] = c[i] ;
    			result[i][0] = ((result[i][1].constMultiply(BigInteger.valueOf(-1))).addConstant(1)).subtract(result[i][2]) ; //a
    		}
    		return result ;
	}
	catch (Exception e) {
			// Throwing an exception
			System.out.println("Exception is caught"+ e);
	}
    	return null;
    }

    /* Implementation of Equality and comparision from "Unconditionally secure constant-rounds multi-party computation from 
    * equality, Comparison, Bits and Exponentiation
    */
    private static PedersonShare BitLT(PedersonShare[] a, PedersonShare[] b, Channel[] channels)throws IOException{
    	PedersonShare[] aBshares = null;
     	PedersonShare[] bBshares = null;
        if(a.length > b.length) {
        	aBshares = a ;
    		bBshares = new PedersonShare[a.length] ;
    		int i ;
    		for(i = 0 ; i < b.length ; i++) bBshares[i] = b[i] ;
    		for(; i < a.length ; i++) bBshares[i] = PedersonComm.shareNumber(BigInteger.ZERO, channels.length/2 , channels) ;
    	}else if(b.length > a.length) {
    		bBshares = b ;
    		aBshares = new PedersonShare[b.length] ;
    		int i ;
    		for(i = 0 ; i < a.length ; i++) aBshares[i] = a[i] ;
    		for(; i < b.length ; i++) aBshares[i] = PedersonComm.shareNumber(BigInteger.ZERO, channels.length/2 , channels) ;
    	}else{
    		aBshares = a ;
    		bBshares = b ;
    	}
        int l = aBshares.length ;
        PedersonShare[] eBshares = new PedersonShare[l] ;
        for(int i = 0 ; i < l ; i++) eBshares[l-i-1] = XOR(aBshares[i],bBshares[i],channels);
        PedersonShare[] temp = PRE_OR(eBshares,channels);
        PedersonShare[] fBshares = new PedersonShare[l];
        for(int i = 0 ; i < l ; i++) fBshares[i] = temp[l-i-1] ;
    	PedersonShare[] gBshares = new PedersonShare[l] ; 
    	PedersonShare[] hBshares = new PedersonShare[l];
    	gBshares[l-1] = fBshares[l-1];
    	for(int i = 0 ; i < l-1; i++) {
    		gBshares[i] = fBshares[i].subtract(fBshares[i+1]);
    	}
    	for(int i = 0 ; i < l ; i++) hBshares[i] = PedersonComm.multiply(gBshares[i],bBshares[i],channels);
    	PedersonShare H = hBshares[0] ;
    	for(int i = 1 ; i < l ; i++) H = H.add(hBshares[i]) ; 
    	return H;
    }
    
    private static PedersonShare XOR(PedersonShare a, PedersonShare b, Channel[] channels) throws IOException {
    	PedersonShare d = a.subtract(b) ;
    	PedersonShare result = PedersonComm.multiply(d,d,channels) ;
    	return result ;
    }
    
    private static PedersonShare[] PRE_OR(PedersonShare[] aBshares, Channel[] channels)throws IOException{ 
    	int l = aBshares.length ;
    	int lambda = (int)Math.ceil(Math.sqrt(l));
    	PedersonShare oneShares = PedersonComm.shareNumber(BigInteger.ONE, channels.length/2 , channels) ;
    	PedersonShare[] xBshares = new PedersonShare[lambda] ;
    	int numberOfRows = 0 ;
    	for(int i = 0 , k = 0 ; i < lambda ; i++) { 
    		PedersonShare temp = oneShares ;
    		for(int j = 0 ; j < lambda && k < l ; j++) {
    			k = lambda*i + j ;
    			if(k>=l) continue;
    			temp = PedersonComm.multiply(temp,oneShares.subtract(aBshares[k]),channels) ;
    		}
    		if(i*lambda>=l) continue;
    		numberOfRows++;
    		xBshares[i] = oneShares.subtract(temp) ;
    	}
    	PedersonShare[] yBshares = new PedersonShare[numberOfRows] ;
    	for(int i = 0 ; i < numberOfRows ; i++) { 
    		PedersonShare temp = oneShares ;
    		for(int k = 0 ; k <= i ; k ++) {
    			temp = PedersonComm.multiply(temp,oneShares.subtract(xBshares[k]),channels) ;
    		}
    		yBshares[i] = oneShares.subtract(temp) ;
    	}
    	PedersonShare[] fBshares = new PedersonShare[numberOfRows] ;
    	fBshares[0] = xBshares[0] ;
    	for(int i = 1 ; i < numberOfRows ; i++) fBshares[i] = yBshares[i].subtract(yBshares[i-1]) ;
    	PedersonShare[] gBshares = new PedersonShare[l] ;
    	for(int i = 0 ; i < numberOfRows ; i++) {
    		for(int j = 0 , k = 0 ; j < lambda && k < l ; j++){ 
    			k = i*lambda + j ;
    			if(k>=l) continue;
    			gBshares[k] = PedersonComm.multiply(fBshares[i],aBshares[k],channels);
    		}
    	}
    	PedersonShare[] cBshares = new PedersonShare[lambda] ;
    	for(int j = 0 , k = 0 ; j < lambda ; j++) {
    		cBshares[j] = gBshares[j] ;
    		for(int i = 1 ; i < numberOfRows ; i++){
    			k = i*lambda + j ;
    			if(k >= l ) continue ;
    			cBshares[j] = cBshares[j].add(gBshares[k]) ;
    		}
    	}
    	PedersonShare[] bBshares = new PedersonShare[l] ; //check below step once. what is b.,j?
    	for(int j = 0 ; j < lambda ; j++){
    		PedersonShare temp = oneShares.subtract(cBshares[0]) ;
    		for(int k = 1 ; k <= j ; k ++) {
    			temp = PedersonComm.multiply(temp,oneShares.subtract(cBshares[k]),channels) ;
    		}
    		bBshares[j] = oneShares.subtract(temp) ;
    	}
    	PedersonShare[] sBshares = new PedersonShare[l] ;
    	for(int i = 0 ; i < numberOfRows ; i++) {
    		for(int j = 0 , k = 0 ; j < lambda && k < l ; j++) {
    			k = i* lambda + j ;
    			if(k>=l) continue;
    			sBshares[k] = PedersonComm.multiply(fBshares[i],bBshares[j],channels);
    		}
    	}
    	for(int i = 0 ; i < numberOfRows ; i++)
    		for(int j = 0, k = 0 ; j < lambda && k < l ; j++) {
    			k = i*lambda + j ; 
    			if(k>=l) continue;
    			bBshares[k] = (sBshares[k].add(yBshares[i])).subtract(fBshares[i]) ;
    		}
    	return bBshares ;
    }
    
}
