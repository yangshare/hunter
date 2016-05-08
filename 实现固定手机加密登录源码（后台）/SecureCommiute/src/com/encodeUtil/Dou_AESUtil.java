package com.encodeUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

/**
 * 
 * 功能描述：对称加密算法 AES(该类必须实例化才可实现功能)
 * 
 * 对称加密算法 AES密码学中的高级加密标准（Advanced Encryption Standard，AES），又称 高级加密标准
 * Rijndael加密法，是美国联邦政府采用的一种区块加密标准。这个标准用来替代原先的DES，
 * 已经被多方分析且广为全世界所使用。经过五年的甄选流程，高级加密标准由美国国家标准与 技术研究院（NIST）于2001年11月26日发布于FIPS PUB
 * 197，并在2002年5月26日成为有效的 标准。2006年，高级加密标准已然成为对称密钥加密中最流行的算法之一。
 * 
 * @author 冉椿霖
 * 
 * @Date 2016-2-6 上午03:19:16
 * 
 */
public class Dou_AESUtil {

	// SecretKey 负责保存对称密钥的容器
	private SecretKeySpec skeySpec;
	// Cipher负责完成加密或解密工作
	private Cipher c;
	// 该字节数组负责保存加密的结果
	private byte[] cipherByte;
	// 向量iv,用于增加加密算法强度
	private IvParameterSpec ivps;

	@SuppressWarnings("unused")
	private Dou_AESUtil() {
	}

	/**
	 * privatekey与iv均为64bit
	 * 
	 * @throws Base64DecodingException
	 */
	public Dou_AESUtil(byte[] privatekey, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			Base64DecodingException {
		Security.addProvider(new com.sun.crypto.provider.SunJCE());
		// 使用CBC模式，需要一个向量iv
		ivps = new IvParameterSpec(iv);
		// 生成密钥
		skeySpec = new SecretKeySpec(Base64.decode(Base64.encode(privatekey)),
				"AES");
		// 生成Cipher对象,指定其支持的DES算法
		c = Cipher.getInstance("AES/CBC/ISO10126Padding"); // "算法/模式/补码方式"
	}

	/**
	 * 对字符串加密
	 * 
	 * @param str
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public byte[] encode(byte[] src) throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException {
		// 根据密钥，对Cipher对象进行初始化，ENCRYPT_MODE表示加密模式
		c.init(Cipher.ENCRYPT_MODE, skeySpec, ivps);
		// 加密，结果保存进cipherByte
		cipherByte = c.doFinal(src);
		return cipherByte;
	}

	/**
	 * 对字符串解密
	 * 
	 * @param buff
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public byte[] decode(byte[] encodesrc) throws InvalidKeyException,
			IllegalBlockSizeException, InvalidAlgorithmParameterException {
		// 根据密钥，对Cipher对象进行初始化，DECRYPT_MODE表示加密模式
		c.init(Cipher.DECRYPT_MODE, skeySpec, ivps);
		try {
			cipherByte = c.doFinal(encodesrc);
		} catch (BadPaddingException e) {
			System.err.println("error: privatekey is wrong!");
			return null;
		}
		return cipherByte;
	}

}

/*
 * 01 算法/模式/填充 16字节加密后数据长度 加密内容不满16字节加密后长度 02 AES/CBC/NoPadding 16 不支持 03
 * AES/CBC/PKCS5Padding 32 16 04 AES/CBC/ISO10126Padding 32 16 05
 * AES/CFB/NoPadding 16 原始数据长度 06 AES/CFB/PKCS5Padding 32 16 07
 * AES/CFB/ISO10126Padding 32 16 08 AES/ECB/NoPadding 16 不支持 09
 * AES/ECB/PKCS5Padding 32 16 10 AES/ECB/ISO10126Padding 32 16 11
 * AES/OFB/NoPadding 16 原始数据长度 12 AES/OFB/PKCS5Padding 32 16 13
 * AES/OFB/ISO10126Padding 32 16 14 AES/PCBC/NoPadding 16 不支持 15
 * AES/PCBC/PKCS5Padding 32 16 16 AES/PCBC/ISO10126Padding 32 16
 * 
 * 
 * 
 * CryptoJS supports the following padding schemes:
 * 
 * Pkcs7 (the default) Iso97971 AnsiX923 Iso10126 ZeroPadding NoPadding
 */
