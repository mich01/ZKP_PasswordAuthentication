package com.mich01.zkp;


import java.security.SecureRandom;

public class Main {
    public static final String PassPhrase ="Test";
    public static void main(String[] args)
    {
        int []validChunkSizes ={2,4,8,16,32,64};
        int chunkLimit =validChunkSizes[new SecureRandom().nextInt(validChunkSizes.length)];
        String passText;
        String internalPass;
        String userPass;
        int chunkPosition =new SecureRandom().nextInt(1,chunkLimit);
        String hashParams =":"+chunkPosition+":"+chunkLimit;
        System.out.println("Test is the password to test!");
        StringBuilder passKey = new StringBuilder();
        StringBuilder passHash = new StringBuilder();
        passKey.append(PassPhrase).append(hashParams);
        System.out.println("The Pass Phrase " + passKey);
        passHash.append(new ZkpFunctions().generateNewSecret(passKey.toString()));
        internalPass =passHash.toString();
        System.out.println("The Sub Hash: " + passHash);
        passText = passHash.append(hashParams).toString();
        userPass = new ZkpFunctions().getSecretHash(passText);
        System.out.println("user Password Hash is: "+userPass);
        System.out.println("Comparing the two keys generated");
        new ZkpFunctions().comparePassKeys(userPass,internalPass);
        System.out.println("--------------------------------testing wit random positions--------------------");
        if(new ZkpFunctions().computeAtRandom(userPass))
        {
            System.out.println("SUCCESS, user key is VALID");
        }
        else
        {
            System.err.println("FAILURE, user key is INVALID");
        }
    }
}
