package com.founder.mobileinternet.cmsinterface.ui.controller;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


import org.apache.commons.collections.bag.SynchronizedSortedBag;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;

public class GPJRSA {
    /**
     * 指定加密算法为RSA
     */
    private static final String ALGORITHM = "RSA";
    /**
     * 密钥长度，用来初始化
     */
    private static final int KEYSIZE = 1024;

    /**
     * 秘钥文件存放的目录
     */
    private static final String KEY_FILE_DIR = "D:/";
    /**
     * 指定公钥存放文件
     */
    private static String PUBLIC_KEY_FILE = "PublicKey";
    /**
     * 指定私钥存放文件
     */
    private static String PRIVATE_KEY_FILE = "PrivateKey";


    /**
     * 生成密钥对
     *
     * @throws Exception
     */
    private static void generateKeyPair() throws Exception {

        /** RSA算法要求有一个可信任的随机数源 */
        SecureRandom secureRandom = new SecureRandom();
        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);

        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
        keyPairGenerator.initialize(KEYSIZE, secureRandom);
//        keyPairGenerator.initialize(KEYSIZE);

        /** 生成密匙对 */
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        /** 得到公钥 */
        Key publicKey = keyPair.getPublic();

        /** 得到私钥 */
        Key privateKey = keyPair.getPrivate();

        OutputStreamWriter oos1 = null;
        OutputStreamWriter oos2 = null;
        try {
            System.out.println(encryptBASE64(publicKey.getEncoded()));
            /** 用对象流将生成的密钥写入文件 */
            oos1 = new OutputStreamWriter(new FileOutputStream(KEY_FILE_DIR + PUBLIC_KEY_FILE));
            oos2 = new OutputStreamWriter(new FileOutputStream(KEY_FILE_DIR + PRIVATE_KEY_FILE));
            oos1.write(encryptBASE64(publicKey.getEncoded()));
            oos2.write(encryptBASE64(privateKey.getEncoded()));
        } catch (Exception e) {
            throw e;
        } finally {
            /** 清空缓存，关闭文件输出流 */
            oos1.close();
            oos2.close();
        }
    }


    //解码返回byte
    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    //编码返回字符串
    public static String encryptBASE64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

    //获取公钥
    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    //获取私钥
    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public Key getPublicKey() throws Exception {
        InputStreamReader in = new InputStreamReader(new FileInputStream(KEY_FILE_DIR + PUBLIC_KEY_FILE));
        char[] val = new char[1024];
        in.read(val);
        String key = new String(val);
        return getPublicKey(key);
    }

    public Key getPrivateKey() throws Exception {
        InputStreamReader in = new InputStreamReader(new FileInputStream(KEY_FILE_DIR + PRIVATE_KEY_FILE));
        char[] val = new char[1024];
        in.read(val);
        String key = new String(val);
        return getPrivateKey(key);
    }

    public String rsaEncrypt(String source) throws Exception {
          
        Key publicKey = getPublicKey();
  
        /** 得到Cipher对象来实现对源数据的RSA加密 */  
        Cipher cipher = Cipher.getInstance(ALGORITHM);  
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
        byte[] b = source.getBytes();  
        /** 执行加密操作 */  
        byte[] b1 = cipher.doFinal(b);  
        return encryptBASE64(b1);
    }

    public String rsaDecrypt(String cryptograph) throws Exception {
          
        Key privateKey = getPrivateKey();
  
        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */  
        Cipher cipher = Cipher.getInstance(ALGORITHM);  
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] b1 = decryptBASE64(cryptograph);
        /** 执行解密操作 */
        byte[] b = cipher.doFinal(b1);  
        return new String(b,"UTF-8");
    }


    public static void main(String[] args) {
        GPJRSA g = new GPJRSA();
        try {
            String m = "is71Hf12sntzJMO9dqPGYejIJIRNFR61P7z1OTbUMF+D8vgiGQ54ZS9Zs3Fu3pbOVct+z1ChQw1uv/LSceTP4WTg+4ksTiPmrOhghZE2b225OhFSb3X2/Ngqkf7UAYV3r9u2ji/2cIa40T6FDKpV85XHkZugEUKGprLZMCOYTWo=";//g.rsaEncrypt("这是一个测试字段");
            String v = g.rsaDecrypt(m);
            System.out.println(m);
            System.out.println(v);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
