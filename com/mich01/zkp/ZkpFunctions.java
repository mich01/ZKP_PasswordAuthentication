package com.mich01.zkp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ZkpFunctions
{
    public String getSecretHash(String passWord)
    {
        String decodedHash =null;
        String decodedSubHash =null;
        int [] index;
        String[] command = passWord.split(":");
        int position = Integer.parseInt(command[1]);
        int chunkSize = Integer.parseInt(command[2]);
        decodedHash = getSHA(Main.PassPhrase);
        index = computeStartEnd(position,chunkSize);
        decodedSubHash = decodedHash.substring(index[0],index[1]);
        System.out.println("The size of the command is: " + decodedHash.length());
        System.out.println("Chunks Position: "+index[0]+" "+index[1]);
        System.out.println("The Hash: " + decodedHash);
        return getSHA(decodedSubHash);
    }

    public boolean computeAtRandom(String passWord)
    {
        boolean Status= false;
        int []validChunkSizes ={2,4,8,16,32,64};
        for(int i=0;i<validChunkSizes.length;i++)
        {
                for (int j = 1; j < validChunkSizes[i]; j++)
                {
                        if (comparePassKeys(getSHA(passWord), getSecret(Main.PassPhrase, validChunkSizes[i], j))) {
                            Status = true;
                            break;
                        } else {
                            System.out.println("---------");
                        }
                }
                if(Status==true)
                {
                    break;
                }
                System.out.println("++++++++++++++++++++++++++++");
        }
        return Status;
    }
    public String getSecret(String passWord, int chunkSize, int position)
    {
        String decodedHash =null;
        String decodedSubHash =null;
        int [] index;
        decodedHash = getSHA(passWord);
        index = computeStartEnd(position,chunkSize);
        decodedSubHash = decodedHash.substring(index[0],index[1]);
        return getSHA(decodedSubHash);
    }

    public String generateNewSecret(String passWord)
    {
        String decodedHash =null;
        String decodedSubHash =null;
        int [] index;
        String[] command = passWord.split(":");
        int position = Integer.parseInt(command[1]);
        int chunkSize = Integer.parseInt(command[2]);
        decodedHash = getSHA(command[0]);
        index = computeStartEnd(position,chunkSize);
        decodedSubHash = decodedHash.substring(index[0],index[1]);
        System.out.println("The size of the command is: " + decodedHash.length());
        System.out.println("Chunks Position: "+index[0]+" "+index[1]);
        System.out.println("The Hash: " + decodedHash);
        return decodedSubHash;
    }
    int[] computeStartEnd(int chunkPosition, int chunks)
    {
        int [] positions = new int[2];
        int chunksSize = 128/chunks;
        positions[0]=(chunksSize*chunkPosition)-(chunksSize);
        positions[1]=(positions[0]+chunksSize);
        return positions;
    }
    String getSHA(String passwordHash)
    {
        String hash=null;
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-512");
            byte[] encodedhash = digest.digest(passwordHash.getBytes(StandardCharsets.UTF_8));
            hash = bytesToHex(encodedhash);
        } catch (NoSuchAlgorithmException ignored) {

        }
        return hash;
    }
    public boolean comparePassKeys(String userPass, String internalHash)
    {
        if(userPass.equals(getSHA(internalHash)))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
