package com.iweike.action;

import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.struts2.ServletActionContext;

import com.opensymphony.xwork2.ActionSupport;

/**
 * className:wUserAction description:该类作用描述 team: 猎赚工作室
 * 
 * @author yangshare
 * @date 2016-5-1上午11:11:28
 */
public class wUserAction extends ActionSupport {

	private static final long serialVersionUID = 1L;

	// 1.前后台通信对象request，response
	HttpServletRequest request = ServletActionContext.getRequest();
	HttpServletResponse response = ServletActionContext.getResponse();
	HttpSession session=request.getSession();
	PrintWriter out = null;
	String name ="";
	String pwd = "";
	String imei="";
	// 2.struts配置返回的json串，必须有set方法配套
	String json = null;

	public String getJson() {
		return json;
	}

	public void setJson(String json) {
		this.json = json;
	}

	public String registers(){
		 try {
			name =new String(request.getParameter("name").getBytes("iso-8859-1"), "utf-8");
			 pwd = request.getParameter("pwd");
			 imei = request.getParameter("imei");
			session.setAttribute("name", name);
			session.setAttribute("IMEI", imei);
			
			System.out.println("用户名：" + name + ",密码:" + pwd + ",IMEI:" + imei
					+ "***********注册成功");
			this.json = "注册成功！";
			return SUCCESS;
		} catch (Exception e) {
			e.printStackTrace();
			return ERROR;
		}
	}

	public String login(){
		 try {
			name = new String(request.getParameter("name").getBytes("iso-8859-1"), "utf-8");
			 pwd = request.getParameter("pwd");
			 imei = request.getParameter("imei");
			
			if(session.getAttribute("name").equals(name)&&session.getAttribute("IMEI").equals(imei)){
				System.out.println("用户名：" + name + ",密码:" + pwd + ",IMEI:" + imei
						+ "***********登录成功");
				this.json = "登录成功！";
				return SUCCESS;
			}else{
				System.out.println("用户名：" + name + ",密码:" + pwd + "正确IMEI:"+session.getAttribute("IMEI")+",当前手机IMEI:" + imei
						+ "***********登录失败");
				this.json = "不是本机登录！";
				return SUCCESS;
			}
		} catch (Exception e) {
			
			e.printStackTrace();
			return ERROR;
		}
			
		
		
	}

}
