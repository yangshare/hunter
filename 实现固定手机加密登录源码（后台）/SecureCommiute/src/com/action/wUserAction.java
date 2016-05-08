package com.action;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.struts2.ServletActionContext;

import com.encodeUtil.Dou_AESUtil;
import com.opensymphony.xwork2.ActionSupport;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

/**
 * className:wUserAction description:该类作用描述 team: 猎赚工作室 //tomcat服务器至少在7.0以上
 * 
 * @author yangshare
 * @date 2016-5-1上午11:11:28
 */
public class wUserAction extends ActionSupport {

	private static final long serialVersionUID = 1L;

	// 1.前后台通信对象request，response
	HttpServletRequest request = ServletActionContext.getRequest();
	HttpServletResponse response = ServletActionContext.getResponse();

	HttpSession session = request.getSession();// session模拟数据库

	// 2.struts配置返回的json串，必须有set方法配套
	String json = null;

	public String getJson() {
		return json;
	}

	public void setJson(String json) {
		this.json = json;
	}

	/**
	 * 功能：注册
	 * 
	 * @return
	 */
	public String registers() {
		try {
			// 获取注册传来的注册信息
			String registername = new String(request.getParameter("name")
					.getBytes("iso-8859-1"), "utf-8");
			String registerpwd = new String(request.getParameter("pwd")
					.getBytes("iso-8859-1"), "utf-8");
			String registerimei = new String(request.getParameter("imei")
					.getBytes("iso-8859-1"), "utf-8");

			// 模拟存入数据库
			session.setAttribute("name", registername);
			session.setAttribute("pwd", registerpwd);
			session.setAttribute("IMEI", registerimei);

			// 存入成功，模拟注册成功
			System.out.println("用户名：" + registername + ",密码:" + registerpwd
					+ ",IMEI:" + registerimei + " 注册成功");

			this.json = "注册成功！";

			return SUCCESS;

		} catch (Exception e) {
			e.printStackTrace();
			return ERROR;
		}
	}

	/**
	 * 功能：登录
	 * 
	 * @return
	 * @throws IOException
	 */
	public String login() throws IOException {

		request.setCharacterEncoding("UTF-8");
		response.setCharacterEncoding("GB2312");

		try {
			// 接受客户端发送的消息(加密状态且已base64编码)
			byte[] bytename = request.getParameter("name").getBytes(
					"iso-8859-1");
			byte[] bytepwd = request.getParameter("pwd").getBytes("iso-8859-1");

			System.out.println("客户端发来的消息(加密状态): name: " + new String(bytename)
					+ "  pwd: " + new String(bytepwd));

			// base64解码
			bytename = Base64.decode(bytename);
			bytepwd = Base64.decode(bytepwd);

			// 解密消息，解密后为byte类型
			String privatekey = (String) session.getAttribute("IMEI");
			bytename = new Dou_AESUtil(privatekey.getBytes(), privatekey
					.replace("0", "1").getBytes()).decode(bytename);
			bytepwd = new Dou_AESUtil(privatekey.getBytes(), privatekey
					.replace("0", "1").getBytes()).decode(bytepwd);

			// 将byte类型数据包装成String
			String name = new String(bytename, "UTF-8");
			String pwd = new String(bytepwd, "UTF-8");

			System.out.println("客户端发来的消息(解密状态)： name: " + name + "  pwd: "
					+ pwd);

			// 判断"数据库"的值与用户输入的值是否匹配
			if (session.getAttribute("name").equals(name)
					&& session.getAttribute("pwd").equals(pwd)) {
				System.out.println("用户名：" + name + ",密码:" + pwd + " 登录成功！");

				// 返回消息到客户端,以下是对数据进行加密
				byte[] bytes = new Dou_AESUtil(privatekey.getBytes("UTF-8"),
						privatekey.replace("0", "1").getBytes())
						.encode(("本机登录，登录成功！").getBytes("UTF-8"));

				// 将数据编码为Base64
				String send = Base64.encode(bytes).replace("\r", "").replace(
						"\n", "").replace("\t", "");
				System.out.println("服务器发出的消息(加密状态)： " + send);

				this.json = send;

			} else {
				System.out.println("用户名：" + name + ",密码:" + pwd + "正确IMEI:"
						+ session.getAttribute("IMEI") + " 登录失败！");

				// 返回消息到客户端,以下是对数据进行加密
				byte[] bytes = new Dou_AESUtil(privatekey.getBytes("UTF-8"),
						privatekey.replace("0", "1").getBytes())
						.encode(("不是本机登录，登录失败！").getBytes());

				// 将数据编码为Base64
				String send = Base64.encode(bytes).replace("\r", "").replace(
						"\n", "").replace("\t", "");
				System.out.println("服务器发出的消息(加密状态)： " + send);

				this.json = send;
			}
			return SUCCESS;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (Base64DecodingException e) {
			e.printStackTrace();
		}
		return SUCCESS;

	}
}
