package com.liyuliang.myutil;

import android.annotation.SuppressLint;
import android.content.ContentResolver;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkInfo;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;

public class EthernetUtil {

    /**
     * 设置以太网动态获取IP
     */
    public static boolean setDynamicIp(Context context) {
        try {
            @SuppressLint("PrivateApi") Class<?> ethernetManagerCls = Class.forName("android.net.EthernetManager");
            //获取EthernetManager实例
            @SuppressLint("WrongConstant") Object ethManager = context.getSystemService("ethernet");
            //创建IpConfiguration
            @SuppressLint("PrivateApi") Class<?> ipConfigurationCls = Class.forName("android.net.IpConfiguration");
            Object ipConfiguration = ipConfigurationCls.newInstance();
            //获取ipAssignment、proxySettings的枚举值
            Map<String, Object> ipConfigurationEnum = getIpConfigurationEnum(ipConfigurationCls);
            //设置ipAssignment
            Field ipAssignment = ipConfigurationCls.getField("ipAssignment");
            ipAssignment.set(ipConfiguration, ipConfigurationEnum.get("IpAssignment.DHCP"));
            //设置proxySettings
            Field proxySettings = ipConfigurationCls.getField("proxySettings");
            proxySettings.set(ipConfiguration, ipConfigurationEnum.get("ProxySettings.NONE"));
            //获取EthernetManager的setConfiguration()
            Method setConfigurationMethod = ethernetManagerCls.getDeclaredMethod("setConfiguration", ipConfiguration.getClass());
            //设置动态IP
            setConfigurationMethod.invoke(ethManager, ipConfiguration);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 设置以太网静态IP地址
     *
     * @param address ip地址
     * @param mask    子网掩码
     * @param gate    网关
     * @param dns     dns
     */
    public static boolean setEthernetStaticIp(Context context, String address, String mask, String gate, String dns) {
        try {
            @SuppressLint("PrivateApi") Class<?> ethernetManagerCls = Class.forName("android.net.EthernetManager");
            //获取EthernetManager实例
            @SuppressLint("WrongConstant") Object ethManager = context.getSystemService("ethernet");
            //创建StaticIpConfiguration
            Object staticIpConfiguration = newStaticIpConfiguration(address, gate, mask, dns);
            //创建IpConfiguration
            Object ipConfiguration = newIpConfiguration(staticIpConfiguration);
            //获取EthernetManager的setConfiguration()
            Method setConfigurationMethod = ethernetManagerCls.getDeclaredMethod("setConfiguration", ipConfiguration.getClass());
            //保存静态ip设置
            saveIpSettings(context, address, mask, gate, dns);
            //设置静态IP
            setConfigurationMethod.invoke(ethManager, ipConfiguration);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    /**
     * 获取StaticIpConfiguration实例
     */
    private static Object newStaticIpConfiguration(String address, String gate, String mask, String dns) throws Exception {
        @SuppressLint("PrivateApi") Class<?> staticIpConfigurationCls = Class.forName("android.net.StaticIpConfiguration");
        //实例化StaticIpConfiguration
        Object staticIpConfiguration = staticIpConfigurationCls.newInstance();
        Field ipAddress = staticIpConfigurationCls.getField("ipAddress");
        Field gateway = staticIpConfigurationCls.getField("gateway");
        Field domains = staticIpConfigurationCls.getField("domains");
        Field dnsServers = staticIpConfigurationCls.getField("dnsServers");
        //设置ipAddress
        ipAddress.set(staticIpConfiguration, newLinkAddress(address, mask));
        //设置网关
        gateway.set(staticIpConfiguration, InetAddress.getByName(gate));
        //设置掩码
        domains.set(staticIpConfiguration, mask);
        //设置dns
        ArrayList<InetAddress> dnsList = (ArrayList<InetAddress>) dnsServers.get(staticIpConfiguration);
        dnsList.add(InetAddress.getByName(dns));
        return staticIpConfiguration;
    }

    /**
     * 获取LinkAddress实例
     */
    private static Object newLinkAddress(String address, String mask) throws Exception {
        Class<?> linkAddressCls = Class.forName("android.net.LinkAddress");
        Constructor<?> linkAddressConstructor = linkAddressCls.getDeclaredConstructor(InetAddress.class, int.class);
        return linkAddressConstructor.newInstance(InetAddress.getByName(address), getPrefixLength(mask));
    }

    /**
     * 获取IpConfiguration实例
     */
    private static Object newIpConfiguration(Object staticIpConfiguration) throws Exception {
        @SuppressLint("PrivateApi") Class<?> ipConfigurationCls = Class.forName("android.net.IpConfiguration");
        Object ipConfiguration = ipConfigurationCls.newInstance();
        //设置StaticIpConfiguration
        Field staticIpConfigurationField = ipConfigurationCls.getField("staticIpConfiguration");
        staticIpConfigurationField.set(ipConfiguration, staticIpConfiguration);
        //获取ipAssignment、proxySettings的枚举值
        Map<String, Object> ipConfigurationEnum = getIpConfigurationEnum(ipConfigurationCls);
        //设置ipAssignment
        Field ipAssignment = ipConfigurationCls.getField("ipAssignment");
        ipAssignment.set(ipConfiguration, ipConfigurationEnum.get("IpAssignment.STATIC"));
        //设置proxySettings
        Field proxySettings = ipConfigurationCls.getField("proxySettings");
        proxySettings.set(ipConfiguration, ipConfigurationEnum.get("ProxySettings.STATIC"));
        return ipConfiguration;
    }

    /**
     * 获取IpConfiguration的枚举值
     */
    private static Map<String, Object> getIpConfigurationEnum(Class<?> ipConfigurationCls) {
        Map<String, Object> enumMap = new HashMap<>();
        Class<?>[] enumClass = ipConfigurationCls.getDeclaredClasses();
        for (Class<?> enumC : enumClass) {
            Object[] enumConstants = enumC.getEnumConstants();
            if (enumConstants == null) continue;
            for (Object enu : enumConstants) {
                enumMap.put(enumC.getSimpleName() + "." + enu.toString(), enu);
            }
        }
        return enumMap;
    }

    /**
     * 保存静态ip设置
     */
    private static void saveIpSettings(Context context, String address, String mask, String gate, String dns) {
        ContentResolver contentResolver = context.getContentResolver();
        Settings.Global.putString(contentResolver, "ethernet_static_ip", address);
        Settings.Global.putString(contentResolver, "ethernet_static_mask", mask);
        Settings.Global.putString(contentResolver, "ethernet_static_gateway", gate);
        Settings.Global.putString(contentResolver, "ethernet_static_dns1", dns);
    }

    /**
     * 获取长度
     */
    private static int getPrefixLength(String mask) {
        String[] strs = mask.split("\\.");
        int count = 0;
        for (String str : strs) {
            if (str.equals("255")) {
                ++count;
            }
        }
        return count * 8;
    }

    /**
     * 设置以太网拨号
     *
     * @param username 宽带账号
     * @param password 宽带密码
     */
    public static boolean setEthernetPppoe(Context context, String username, String password) {
        String interfaceName = "eth0";
        try {
            @SuppressLint("PrivateApi") Class<?> pppoeManagerCls = Class.forName("android.net.PppoeManager");
            //获取EthernetManager实例
            @SuppressLint("WrongConstant") Object pppoeManager = context.getSystemService("pppoe");
            //获取EthernetManager的setConfiguration()
            Method connect = pppoeManagerCls.getDeclaredMethod("connect", String.class, String.class, String.class);
            //保存静态ip设置
//            saveIpSettings(context, address, mask, gate, dns);
            //设置静态IP
            connect.invoke(pppoeManager, username, password, interfaceName);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 获取以太网MAC地址
     */
    public static String getEthernetMac(String ifname) {
        String ethernetMac = null;
        try {
            NetworkInterface networkInterface = NetworkInterface.getByName(ifname);
            byte[] buf = networkInterface.getHardwareAddress();
            ethernetMac = byteHexString(buf);
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return ethernetMac;
    }

    /**
     * 字节数组转16进制字符串
     */
    public static String byteHexString(byte[] array) {
        StringBuilder builder = new StringBuilder();

        for (byte b : array) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            builder.append(hex);
            builder.append(":");
        }
        if (builder.length() > 0) {
            builder.deleteCharAt(builder.length() - 1);
        }
        return builder.toString().toUpperCase();
    }

    /**
     * 获取IP地址
     */
    public static String getIpAddress() {
        String interfaceName = "eth0";
        try {
            //获取本机所有的网络接口
            Enumeration<NetworkInterface> enNetworkInterface = NetworkInterface.getNetworkInterfaces();
            //判断 Enumeration 对象中是否还有数据
            while (enNetworkInterface.hasMoreElements()) {
                //获取 Enumeration 对象中的下一个数据
                NetworkInterface networkInterface = enNetworkInterface.nextElement();
                // 判断网口是否在使用
                if (!networkInterface.isUp()) {
                    continue;
                }
                // 网口名称是否和需要的相同
                if (!interfaceName.equals(networkInterface.getDisplayName())) {
                    continue;
                }
                //getInetAddresses 方法返回绑定到该网卡的所有的 IP 地址
                Enumeration<InetAddress> enInetAddress = networkInterface.getInetAddresses();
                while (enInetAddress.hasMoreElements()) {
                    InetAddress inetAddress = enInetAddress.nextElement();
                    if (inetAddress instanceof Inet4Address) {
                        //判断是否未ipv4
                        return inetAddress.getHostAddress();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "0.0.0.0";
    }

    /**
     * 获取网关
     */
    public static String getGateWay() {
        String[] arr;
        try {
            Process process = Runtime.getRuntime().exec("ip route list table 0");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String string = in.readLine();
            arr = string.split("\\s+");
            return arr[2];
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "0.0.0.0";
    }

    /**
     * 获取子网掩码
     */
    public static String getNetMask() {
        String interfaceName = "eth0";
        try {
            //获取本机所有的网络接口
            Enumeration<NetworkInterface> networkInterfaceEnumeration = NetworkInterface.getNetworkInterfaces();
            //判断 Enumeration 对象中是否还有数据
            while (networkInterfaceEnumeration.hasMoreElements()) {
                //获取 Enumeration 对象中的下一个数据
                NetworkInterface networkInterface = networkInterfaceEnumeration.nextElement();
                if (networkInterface.isUp() && interfaceName.equals(networkInterface.getDisplayName())) {
                    //判断网口是否在使用，判断是否时我们获取的网口
                    for (InterfaceAddress interfaceAddress : networkInterface.getInterfaceAddresses()) {
                        if (interfaceAddress.getAddress() instanceof Inet4Address) {
                            //仅仅处理ipv4
                            switch (interfaceAddress.getNetworkPrefixLength()) {
                                case 8:
                                    return "255.0.0.0";
                                case 16:
                                    return "255.255.0.0";
                                case 24:
                                    return "255.255.255.0";
                            }
                        }
                    }
                    break;
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return "0.0.0.0";
    }

    /**
     * 获取dns(仅获取IPV4的DNS)
     */
    public static String getDns(Context context) {
        try {
            String[] dnsServers = getDnsFromCmd();
            if (dnsServers.length == 0) {
                dnsServers = getDnsFromConnectionManager(context);
            }
            StringBuilder sb = new StringBuilder();
            for (String dnsServer : dnsServers) {
                sb.append(dnsServer);
                sb.append(",");
            }
            if (sb.length() > 0) {
                sb.deleteCharAt(sb.length() - 1);
                return sb.toString();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "0.0.0.0";
    }

    //通过 getprop 命令获取
    private static String[] getDnsFromCmd() {
        LinkedList<String> dnsServers = new LinkedList<>();
        try {
            Process process = Runtime.getRuntime().exec("getprop");
            InputStream inputStream = process.getInputStream();
            LineNumberReader lnr = new LineNumberReader(new InputStreamReader(inputStream));
            String line;
            while ((line = lnr.readLine()) != null) {
                int split = line.indexOf("]: [");
                if (split == -1) continue;
                String property = line.substring(1, split);
                String value = line.substring(split + 4, line.length() - 1);
                if (property.endsWith(".dns")
                        || property.endsWith(".dns1")
                        || property.endsWith(".dns2")
                        || property.endsWith(".dns3")
                        || property.endsWith(".dns4")) {
                    InetAddress ip = InetAddress.getByName(value);
                    if (ip instanceof Inet4Address) {
                        value = ip.getHostAddress();
                        if (value == null) {
                            continue;
                        }
                        if (value.length() == 0) {
                            continue;
                        }
                        dnsServers.add(value);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dnsServers.isEmpty() ? new String[0] : dnsServers.toArray(new String[0]);
    }


    private static String[] getDnsFromConnectionManager(Context context) {
        LinkedList<String> dnsServers = new LinkedList<>();
        if (context != null) {
            ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (connectivityManager != null) {
                NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
                if (activeNetworkInfo != null) {
                    for (Network network : connectivityManager.getAllNetworks()) {
                        NetworkInfo networkInfo = connectivityManager.getNetworkInfo(network);
                        if (networkInfo != null && networkInfo.getType() == activeNetworkInfo.getType()) {
                            LinkProperties lp = connectivityManager.getLinkProperties(network);
                            for (InetAddress addr : lp.getDnsServers()) {
                                if (addr instanceof Inet4Address) {
                                    dnsServers.add(addr.getHostAddress());
                                }
                            }
                        }
                    }
                }
            }
        }
        return dnsServers.isEmpty() ? new String[0] : dnsServers.toArray(new String[0]);
    }


    @SuppressLint("PrivateApi")
    public static void setEthernet(Context context, boolean open) {
        Class<?> emClass;
        try {
            emClass = Class.forName("android.net.EthernetManager");
            @SuppressLint("WrongConstant") Object emInstance = context.getSystemService("ethernet");
            Method methodSetEthEnabled;
            try {
                methodSetEthEnabled = emClass.getMethod("setEthernetEnabled", Boolean.TYPE);
                methodSetEthEnabled.setAccessible(true);
                try {
                    methodSetEthEnabled.invoke(emInstance, open);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } catch (NoSuchMethodException e) {
                e.printStackTrace();
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /**
     * 判断以太网类型
     */
    public static String getConnectMode(Context context) {
        try {
            @SuppressLint("PrivateApi") Class<?> ethernetManagerCls = Class.forName("android.net.EthernetManager");
            @SuppressLint("PrivateApi") Class<?> ipConfigurationCls = Class.forName("android.net.IpConfiguration");
            @SuppressLint("WrongConstant") Object ethManager = context.getSystemService("ethernet");
            Method getConfiguration = ethernetManagerCls.getDeclaredMethod("getConfiguration");
            Method getIpAssignment = ipConfigurationCls.getDeclaredMethod("getIpAssignment");
            Object config = getConfiguration.invoke(ethManager);
            Object ipAssignment = getIpAssignment.invoke(config);
            //获取ipAssignment、proxySettings的枚举值
            Map<String, Object> ipConfigurationEnum = getIpConfigurationEnum(ipConfigurationCls);
            if (Objects.equals(ipConfigurationEnum.get("IpAssignment.STATIC"), ipAssignment)) {
                return "STATIC";
            } else if (Objects.equals(ipConfigurationEnum.get("IpAssignment.DHCP"), ipAssignment)) {
                return "DHCP";
            } else if (Objects.equals(ipConfigurationEnum.get("IpAssignment.PPPOE"), ipAssignment)) {
                return "PPPOE";
            } else if (Objects.equals(ipConfigurationEnum.get("IpAssignment.UNASSIGNED"), ipAssignment)) {
                return "UNASSIGNED";
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "UNASSIGNED";
    }

}